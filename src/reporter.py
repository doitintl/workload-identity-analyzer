import logging
from functools import wraps

logger = logging.getLogger()

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
