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

class FleetWorkload(GkeWorkload):
    """docstring for FleetWorkload"""

    def __init__(self, args, reporter):
        super(FleetWorkload, self).__init__(args, reporter)

    @Reporter.check_decorator('Could not find WI pool/Identity provider '
                              'info on GKE Fleet Membership')
    def check_cluster(self):
        self.membership_name = self.cluster_name.replace(
            'clusters', 'memberships')
        service = googleapiclient.discovery.build(
            'gkehub', 'v1', cache_discovery=False)
        m = service.projects().locations().memberships().get(
            name=self.membership_name).execute()
        try:
            self.wi_pool = m['authority']['workloadIdentityPool']
            self.idp = m['authority']['identityProvider']
        except KeyError:
            self.check_failed = True

    @Reporter.check_decorator('Pod found in current context')
    def check_pod(self):
        try:
            self.pod = self.v1.read_namespaced_pod(
                self.args.pod, self.namespace)
            self.ksa_name = self.pod.spec.service_account_name
        except client.exceptions.ApiException:
            logger.error('Failed to find pod %s/%s in current context\n' %
                         (self.namespace, self.args.pod))
            self.check_failed = True

    @Reporter.check_decorator('WI projected KSA volume found in pod spec')
    def check_volume_wi(self):
        try:
            volumes = [v for v in self.pod.spec.volumes
                       if hasattr(v.projected, 'sources')]
            self.volume = [volume for volume in volumes
                           for s in volume.projected.sources
                           if hasattr(s.service_account_token, 'audience') and
                           s.service_account_token.audience == self.wi_pool][0]
            self.volume_name = self.volume.name
            self.ksa_token_path = [source.service_account_token for source
                                   in self.volume.projected.sources
                                   if source.service_account_token][0].path
            logger.debug(self.volume)
        except (AttributeError, KeyError):
            logger.error('Pod spec is missing the projected GCP '
                         'Workload Identity KSA volume\n')
            self.check_failed = True

    @Reporter.check_decorator('WI projected KSA volume has ConfigMap source\n')
    def check_volume_cm(self):
        try:
            self.cm = [source.config_map for source in
                       self.volume.projected.sources if source.config_map][0]
            logger.debug(self.cm)
        except (AttributeError, KeyError):
            logger.error('ConfigMap source is missing from the projected '
                         'GCP Workload Identity KSA volume\n')
            self.check_failed = True

    @Reporter.check_decorator('Pod spec has container/s with the '
                              'KSA volume mounted')
    def check_container_volume_mounts(self):
        try:
            self.containers = [container for container in
                               self.pod.spec.containers for vm in
                               container.volume_mounts if hasattr(vm, 'name')
                               and vm.name == self.volume.name]
            logger.debug(self.containers)
            # assuming that all containers mount the KSA in the same path
            self.base_mount_path = [vm.mount_path for vm in
                                    self.containers[0].volume_mounts
                                    if vm.name == self.volume_name][0]
            logger.debug(self.base_mount_path)
        except (AttributeError, KeyError):
            logger.error('None of the pod containers '
                         'mounts the WI KSA volume\n')
            self.check_failed = True

    @Reporter.check_decorator('WI KSA volume found in pod spec')
    def check_configmap(self):
        # check client json configmap
        pass

    @Reporter.check_decorator('"GOOGLE_APPLICATION_CREDENTIALS" environment '
                              'variable set correctly')
    def check_env_variable(self):
        pass
