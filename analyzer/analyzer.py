#!/usr/bin/env python3

import os
import re
import argparse
import logging
import googleapiclient.discovery
from functools import wraps
from kubernetes import client, config
from googleapiclient.errors import HttpError


def parse_args():
    parser = argparse.ArgumentParser(
        description='GKE Workload Identity Analyzer')
    parser.add_argument('pod', help='Kubernetes Pod name to check', type=str)
    parser.add_argument('-n', '--namespace',
                        help='Kubernetes Namespace to run in', type=str)
    parser.add_argument('-p', '--project',
                        help='GCP Project holding the cluster', type=str)
    parser.add_argument('-l', '--location',
                        help='The GCP location of the cluster', type=str)
    parser.add_argument('-c', '--cluster',
                        help='The name of the cluster', type=str)
    parser.add_argument('-d', '--debug', help='Enable debug logging',
                        action='store_true')
    args = parser.parse_args()
    inclusive_group = [args.project, args.location, args.cluster]
    if (all(v is not None for v in inclusive_group) or
            all(v is None for v in inclusive_group)):
        return args
    parser.error(
        'Either set all, or none of: "PROJECT", "LOCATION", "CLUSTER"')


def init_logger(args):
    global logger
    level = logging.DEBUG if os.environ.get(
        'DEBUG', args.debug) else logging.INFO
    logging.basicConfig(level=level, format='%(message)s')
    logger = logging.getLogger(name='analyzer')


class Reporter(object):
    """This class represents an analysis reporter"""

    def __init__(self):
        super(Reporter, self).__init__()
        self.entries = []

    def check_decorator(msg):
        def check_wrapper(func):
            @wraps(func)
            def report(*args, **kwargs):
                if args[0].check_failed:
                    skipped = True
                else:
                    skipped = False
                    func(*args, **kwargs)
                args[0].reporter.add_entry(args[0].check_failed, skipped, msg)
            return report
        return check_wrapper

    def add_entry(self, failed, skipped, msg):
        if skipped:
            status = '-'
        elif failed:
            status = 'X'
        else:
            status = 'V'
        self.entries.append({
            'status': status,
            'message': msg
        })

    def is_passing(self):
        return all([e['status'] == 'V' for e in self.entries])

    def print_report(self, gke, project):
        logger.info('Check results')
        logger.info('---------------------------')
        logger.info('V=Passed, X=Failed, -=Skipped\n')
        for e in self.entries:
            logger.info('[%s] %s' % (e['status'], e['message']))
        logger.info('')
        logger.info('GKE cluster info')
        logger.info('---------------------------')
        gke.print_info()
        logger.info('')
        logger.info('Google Service Account info')
        logger.info('---------------------------')
        project.print_info()
        logger.info('')
        if self.is_passing():
            project.list_gsa_project_roles()
            logger.info('Workload Identity configured properly - check '
                        'if any IAM roles are missing from the list above')


class GkeWorkload(object):
    """This class represents a workload running in GKE"""
    node_label = 'iam.gke.io/gke-metadata-server-enabled'
    ksa_annotation = 'iam.gke.io/gcp-service-account'

    def __init__(self, args, reporter):
        super(GkeWorkload, self).__init__()
        self.args = args
        self.reporter = reporter
        self.check_failed = False
        self.cluster = None
        self.cluster_name = None
        self.gsa = None
        self.ksa_name = None
        self.namespace = None
        self.node = None
        self.node_name = None
        self.project = None
        config.load_kube_config()
        self.set_gke_info()
        self.set_namespace()
        self.v1 = client.CoreV1Api()

    @Reporter.check_decorator('GCP project and GKE info '
                              'determined from current context')
    def set_gke_info(self):
        if self.args.project:
            self.project = self.args.project
            self.location = self.args.location
            self.cluster_name = 'projects/%s/locations/%s/clusters/%s' % (
                self.args.project, self.args.location, self.args.cluster)
            return
        try:
            c = config.list_kube_config_contexts(
            )[1]['context']['cluster'].split('_')
            _, project, location, cluster = c
            self.project = project
            self.cluster_name = 'projects/%s/locations/%s/clusters/%s' % (
                project, location, cluster)
        except:
            logger.error('Failed to get cluster info from current context, '
                         'or it was not passed as arguments\n')
            self.check_failed = True

    @Reporter.check_decorator('Namespace passed as argument,'
                              'or determined from current context')
    def set_namespace(self):
        if self.args.namespace:
            self.namespace = self.args.namespace
            return
        try:
            self.namespace = config.list_kube_config_contexts()[
                1]['context']['namespace']
        except:
            logger.error('Failed to get NS from current context\n')
            self.check_failed = True

    def get_gsa(self):
        return self.gsa

    def get_project(self):
        return self.project

    def get_ksa_string(self):
        return 'serviceAccount:%s.svc.id.goog[%s/%s]' % (
            self.project, self.namespace, self.ksa_name)

    def get_check_status(self):
        return self.check_failed

    def print_info(self):
        if self.cluster_name:
            logger.info('Cluster: "%s"' % self.cluster_name)
            logger.info('Workload: "%s/%s" running on Node: "%s"' %
                        (self.namespace, self.args.pod, self.node_name))
            logger.info('KSA name: "%s"' % self.ksa_name)
        else:
            logger.info('Cluster info could not be determined, '
                        'is your current context set correctly?')

    @Reporter.check_decorator('Workload Identity enabled on GKE Cluster')
    def check_cluster(self):
        service = googleapiclient.discovery.build(
            'container', 'v1', cache_discovery=False)
        c = service.projects().locations().clusters().get(
            name=self.cluster_name).execute()
        try:
            wi_pool = c['workloadIdentityConfig']['workloadPool']
        except KeyError:
            self.check_failed = True

    @Reporter.check_decorator('Pod found in current context')
    def check_pod(self):
        try:
            pod = self.v1.read_namespaced_pod(self.args.pod, self.namespace)
            self.ksa_name = pod.spec.service_account_name
            self.node_name = pod.spec.node_name
        except client.exceptions.ApiException:
            logger.error('Failed to find pod %s/%s in current context\n' %
                         (self.namespace, self.args.pod))
            self.check_failed = True

    @Reporter.check_decorator('GKE Node found in the cluster')
    def check_node(self):
        logger.debug('Pod is running on node %s' % self.node_name)
        try:
            n = self.v1.read_node(self.node_name)
            self.node = n
        except client.exceptions.ApiException:
            logger.error('Failed to get Node %s from the API\n' %
                         self.node_name)
            self.check_failed = True

    @Reporter.check_decorator('Workload Identity enabled on Node Pool')
    def check_node_labels(self):
        try:
            if not bool(self.node.metadata.labels[self.node_label]):
                self.check_failed = True
        except KeyError:
            self.check_failed = True

    @Reporter.check_decorator('KSA found in the cluster')
    def check_ksa(self):
        logger.debug('Pod spec is using KSA "%s"' % self.ksa_name)
        try:
            self.ksa = self.v1.read_namespaced_service_account(
                self.ksa_name, self.namespace)
        except client.exceptions.ApiException:
            logger.error('Failed to get KSA %s from the API\n' % self.ksa_name)
            self.check_failed = True

    @Reporter.check_decorator('KSA Workload Identity annotation set correctly')
    def check_ksa_annotation(self):
        try:
            gsa = self.ksa.metadata.annotations[self.ksa_annotation]
            self.gsa = gsa
        except (TypeError, KeyError):
            self.check_failed = True


class GsaProject(object):
    """This class represents a GCP Project in which a GSA resides"""

    def __init__(self, reporter, gsa, ksa_string, project, check_failed):
        super(GsaProject, self).__init__()
        self.check_failed = check_failed
        self.reporter = reporter
        self.gsa = gsa
        self.ksa_string = ksa_string
        self.project = self.get_project(project)
        self.gsa_link = 'projects/%s/serviceAccounts/%s' % (
            self.project, self.gsa)
        self.gsa_status = None
        self.wi_users = []
        self.iam = googleapiclient.discovery.build(
            'iam', 'v1', cache_discovery=False)

    def get_project(self, project):
        # will try to extract the Project ID from GSA email
        pattern = r'(?:.+@)(([a-z]|-){6,30})(?:\.iam\.gserviceaccount\.com$)'
        try:
            p = re.search(pattern, self.gsa)
        except TypeError:
            p = None
        if p:
            gsa_project = p.groups()[0]
            logger.debug('GSA is in a different GCP project: %s' % gsa_project)
            return gsa_project
        else:
            return project

    def print_info(self):
        if self.gsa:
            logger.info('Google Service Account: "%s"' % self.gsa_link)
            logger.info('Has the following Workload Identity Users:\n%s' %
                        '\n'.join(self.wi_users))
        else:
            logger.info('Google Service Account information could '
                        'not be determined, fix previous issues')

    @Reporter.check_decorator('GSA found in GCP project')
    def check_gsa(self):
        try:
            self.gsa_status = self.iam.projects().serviceAccounts().get(
                name=self.gsa_link).execute()
        except HttpError:
            logger.error('Failed to get GSA %s\n' % self.gsa_link)
            self.check_failed = True

    @Reporter.check_decorator('GSA is enabled')
    def check_gsa_enabled(self):
        if self.gsa_status.get('disabled'):
            self.check_failed = True

    @Reporter.check_decorator('GSA has Workload Identity users configured')
    def check_gsa_iam_policy(self):
        gsa_policy = self.iam.projects().serviceAccounts().getIamPolicy(
            resource=self.gsa_link).execute()
        try:
            self.wi_users = [
                b['members'] for b in gsa_policy['bindings']
                if b['role'] == 'roles/iam.workloadIdentityUser'][0]
        except (IndexError, KeyError):
            self.check_failed = True

    @Reporter.check_decorator('GSA does not have KSA '
                              'as a Workload Identity user')
    def check_gsa_ksa_workload_identity_user(self):
        if self.ksa_string not in self.wi_users:
            self.check_failed = True

    def list_gsa_project_roles(self):
        service = googleapiclient.discovery.build(
            'cloudresourcemanager', 'v1', cache_discovery=False
        )
        project_policy = service.projects(
        ).getIamPolicy(resource=self.project).execute()
        gsa_roles = [b['role'] for b in project_policy['bindings']
                     if 'serviceAccount:%s' % self.gsa in b['members']]
        logger.debug(project_policy)
        if gsa_roles:
            logger.info('GSA: "%s" has the following roles '
                        'in project "%s":\n%s' %
                        (self.gsa, self.project, '\n'.join(gsa_roles)))
        else:
            logger.error('GSA: "%s" has no permissions in project "%s"\n' % (
                self.gsa, self.project))


def main():
    args = parse_args()
    init_logger(args)
    logger.debug(args)
    reporter = Reporter()

    gke = GkeWorkload(args, reporter)
    gke.check_cluster()
    gke.check_pod()
    gke.check_node()
    gke.check_node_labels()
    gke.check_ksa()
    gke.check_ksa_annotation()

    project = GsaProject(
        reporter, gke.get_gsa(),
        gke.get_ksa_string(),
        gke.get_project(),
        gke.get_check_status())
    project.check_gsa()
    project.check_gsa_enabled()
    project.check_gsa_iam_policy()
    project.check_gsa_ksa_workload_identity_user()

    reporter.print_report(gke, project)


if __name__ == '__main__':
    main()
