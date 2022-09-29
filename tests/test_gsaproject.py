import unittest
from unittest.mock import MagicMock, patch
from gsa import GsaProject
from analyzer import parse_args, init_logger
from reporter import Reporter


@patch('googleapiclient.discovery.build')
class GsaProjectTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        args = parse_args()
        init_logger(args)

    def init_gsa_project(self, gsa=None, ksa=None, project=None):
        return GsaProject(Reporter(), gsa, ksa, project, False)

    def test_get_project(self, mock_build):
        # Project extracted from GSA email
        gsaProject = self.init_gsa_project(project='test-project',
                                           gsa='foo@test-gsa-project'
                                           '.iam.gserviceaccount.com')
        self.assertEqual(gsaProject.project, 'test-gsa-project')
        # Project falls back to GKE project
        gsaProject = self.init_gsa_project(project='test-project',
                                           gsa='invalid@gsa.email')
        self.assertEqual(gsaProject.project, 'test-project')

    def test_check_gsa_link(self, mock_build):
        gsaProject = self.init_gsa_project(
            gsa='foo@test-project.iam.gserviceaccount.com')
        self.assertEqual(gsaProject.gsa_link,
                         'projects/test-project/serviceAccounts/'
                         'foo@test-project.iam.gserviceaccount.com')

    def test_check_gsa_enabled(self, mock_build):
        gsaProject = self.init_gsa_project()
        mock_build.return_value.projects.return_value.serviceAccounts\
            .return_value.get.return_value.execute.return_value = {
                'disabled': False}
        gsaProject.check_gsa()
        self.assertFalse(gsaProject.check_failed)
        gsaProject.check_gsa_enabled()
        self.assertFalse(gsaProject.check_failed)

    def test_check_gsa_disabled(self, mock_build):
        gsaProject = self.init_gsa_project()
        mock_build.return_value.projects.return_value.serviceAccounts\
            .return_value.get.return_value.execute.return_value = {
                'disabled': True}
        gsaProject.check_gsa()
        self.assertFalse(gsaProject.check_failed)
        gsaProject.check_gsa_enabled()
        self.assertTrue(gsaProject.check_failed)

    def test_check_gsa_iam_policy_success(self, mock_build):
        gsaProject = self.init_gsa_project()
        mock_build.return_value.projects.return_value.serviceAccounts\
            .return_value.getIamPolicy.return_value.execute.return_value = {
                'bindings': [{'role': 'roles/iam.workloadIdentityUser',
                              'members': ['serviceAccount:test.svc'
                                          '.id.goog[test/test]']}]}
        gsaProject.check_gsa_iam_policy()
        self.assertFalse(gsaProject.check_failed)

    def test_check_gsa_iam_policy_fail(self, mock_build):
        gsaProject = self.init_gsa_project()
        mock_build.return_value.projects.return_value.serviceAccounts\
            .return_value.getIamPolicy.return_value.execute.return_value = {}
        gsaProject.check_gsa_iam_policy()
        self.assertTrue(gsaProject.check_failed)

    def test_check_gsa_ksa_workload_identity_user_success(self, mock_build):
        gsaProject = self.init_gsa_project(ksa='serviceAccount:test.svc'
                                           '.id.goog[test/test]')
        mock_build.return_value.projects.return_value.serviceAccounts\
            .return_value.getIamPolicy.return_value.execute.return_value = {
                'bindings': [{'role': 'roles/iam.workloadIdentityUser',
                              'members': ['serviceAccount:test.svc'
                                          '.id.goog[test/test]']}]}
        gsaProject.check_gsa_iam_policy()
        self.assertFalse(gsaProject.check_failed)
        gsaProject.check_gsa_ksa_workload_identity_user()
        self.assertFalse(gsaProject.check_failed)

    def test_check_gsa_ksa_workload_identity_user_fail(self, mock_build):
        gsaProject = self.init_gsa_project(ksa='serviceAccount:test.svc'
                                           '.id.goog[test/test]')
        mock_build.return_value.projects.return_value.serviceAccounts\
            .return_value.getIamPolicy.return_value.execute.return_value = {
                'bindings': [{'role': 'roles/iam.workloadIdentityUser',
                              'members': ['serviceAccount:test.svc'
                                          '.id.goog[another/another]']}]}
        gsaProject.check_gsa_iam_policy()
        self.assertFalse(gsaProject.check_failed)
        gsaProject.check_gsa_ksa_workload_identity_user()
        self.assertTrue(gsaProject.check_failed)

    def test_list_gsa_project_roles(self, mock_build):
        gsaProject = self.init_gsa_project(
            gsa='testMember', project='test-project')
        mock_build.return_value.projects.return_value.getIamPolicy\
            .return_value.execute.return_value = {
                'bindings': [
                    {'role': 'roles/viewer',
                     'members': ['serviceAccount:testMember']},
                    {'role': 'roles/editor',
                     'members': ['serviceAccount:testMember']}
                ]
            }
        with self.assertLogs() as cm:
            gsaProject.list_gsa_project_roles()
        self.assertEqual(cm.output, [
                         'INFO:root:GSA: "testMember" has the following '
                         'roles in project "test-project":'
                         '\nroles/viewer\nroles/editor'])


if __name__ == '__main__':
    unittest.main()
