import logging
import googleapiclient.discovery
from kubernetes import client, config
from reporter import Reporter

logger = logging.getLogger()

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
