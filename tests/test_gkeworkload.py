import unittest
from unittest.mock import MagicMock, patch
from gke import GkeWorkload
from analyzer import parse_args, init_logger
from reporter import Reporter


class GkeWorkloadTestCase(unittest.TestCase):
    PROJECT_NAME = 'test-project'
    LOCATION = 'test-location'
    CLUSTER = 'test-cluster'
    NAMESPACE = 'test-namespace'
    KSA = 'test-ksa'
    CONTEXT = {'context':
               {'cluster':
                'gke_%s_%s_%s' % (PROJECT_NAME, LOCATION, CLUSTER),
                'namespace': NAMESPACE}}

    @classmethod
    def setUpClass(self):
        args = parse_args()
        init_logger(args)
        with patch('kubernetes.config.load_kube_config'):
            with patch('kubernetes.config.list_kube_config_contexts',
                       return_value=({}, self.CONTEXT)):
                self.gkeWorkload = GkeWorkload(args, Reporter())

    def setUp(self):
        self.gkeWorkload.check_failed = False

    def test_cluster_name(self):
        self.assertEqual(self.gkeWorkload.cluster_name,
                         'projects/%s/locations/%s/clusters/%s' % (
                             self.PROJECT_NAME, self.LOCATION, self.CLUSTER))

    def test_namespace_name(self):
        self.assertEqual(self.gkeWorkload.namespace, self.NAMESPACE)

    @patch('googleapiclient.discovery.build')
    def test_check_cluster(self, mock_build):
        self.gkeWorkload.check_cluster()
        self.assertFalse(self.gkeWorkload.check_failed)

    def test_check_pod(self):
        pod = MagicMock()
        pod.spec.service_account_name = self.KSA
        pod.spec.node_name = 'test-node'
        with patch.object(self.gkeWorkload.v1, 'read_namespaced_pod',
                          return_value=pod):
            self.gkeWorkload.check_pod()
        self.assertFalse(self.gkeWorkload.check_failed)
        self.assertEqual(self.gkeWorkload.ksa_name, self.KSA)
        self.assertEqual(self.gkeWorkload.node_name, 'test-node')

    def test_check_node(self):
        node = MagicMock()
        node.metadata.labels = {
            self.gkeWorkload.node_label: 'test'
        }
        with patch.object(self.gkeWorkload.v1, 'read_node', return_value=node):
            self.gkeWorkload.check_node()
        self.assertFalse(self.gkeWorkload.check_failed)
        self.gkeWorkload.check_node_labels()
        self.assertFalse(self.gkeWorkload.check_failed)

    def test_check_node_fail(self):
        node = MagicMock()
        node.metadata.labels = {
            'wrong-label': 'test'
        }
        with patch.object(self.gkeWorkload.v1, 'read_node', return_value=node):
            self.gkeWorkload.check_node()
        self.assertFalse(self.gkeWorkload.check_failed)
        self.gkeWorkload.check_node_labels()
        self.assertTrue(self.gkeWorkload.check_failed)

    def test_check_ksa(self):
        ksa = MagicMock()
        ksa.metadata.annotations = {
            self.gkeWorkload.ksa_annotation: 'test'
        }
        with patch.object(self.gkeWorkload.v1,
                          'read_namespaced_service_account',
                          return_value=ksa):
            self.gkeWorkload.check_ksa()
        self.assertFalse(self.gkeWorkload.check_failed)
        self.gkeWorkload.check_ksa_annotation()
        self.assertFalse(self.gkeWorkload.check_failed)

    def test_check_ksa_fail(self):
        ksa = MagicMock()
        ksa.metadata.annotations = {
            'wrong-annotation': 'test'
        }
        with patch.object(self.gkeWorkload.v1,
                          'read_namespaced_service_account',
                          return_value=ksa):
            self.gkeWorkload.check_ksa()
        self.assertFalse(self.gkeWorkload.check_failed)
        self.gkeWorkload.check_ksa_annotation()
        self.assertTrue(self.gkeWorkload.check_failed)


if __name__ == '__main__':
    unittest.main()
