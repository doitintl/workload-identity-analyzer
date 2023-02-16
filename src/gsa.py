import re
import logging
import googleapiclient.discovery
from googleapiclient.errors import HttpError
from reporter import Reporter

logger = logging.getLogger()


def format_wi_user(user):
    try:
        match = re.search(r'\[([\w-]+/[\w-]+)\]$', user)
    except TypeError:
        match = None
    if match:
        namespace, ksa = match.group(1).split('/')
        return '%s (Namespace: %s, KSA: %s)' % (user, namespace, ksa)
    else:
        return '%s (Namespace and KSA could not be determined - wrong binding?)' % user


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
                        '\n'.join(map(format_wi_user, self.wi_users)))
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
