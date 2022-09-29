#!/usr/bin/env python3

import os
import argparse
import logging
from gke import GkeWorkload
from gsa import GsaProject
from reporter import Reporter

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
    level = logging.DEBUG if os.environ.get(
        'DEBUG', args.debug) else logging.INFO
    logging.basicConfig(level=level, format='%(message)s')
    return logging.getLogger(name='analyzer')



def main():
    args = parse_args()
    logger = init_logger(args)
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
