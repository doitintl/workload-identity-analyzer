## GKE Workload Identity Analyzer

This script takes a Pod name (running in the current context) and performs checks to ensure that [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) is properly configured.

### Performed checks

- Workload Identity enabled on the GKE cluster
- Pod has `.spec.serviceAccountName` configured
- KSA (configured in previous step) exists
- KSA is annotated correctly with a GSA
- GSA (configured in previous step) exists in the project
- KSA has `roles/iam.workloadIdentityUser` on the GSA
- GSA IAM roles in the project

[![Supported Versions](https://img.shields.io/pypi/pyversions/wi-analyzer.svg)](https://pypi.org/project/wi-analyzer)

## Prerequisites

- [`gcloud` cli](https://cloud.google.com/sdk/docs/install) installed and configured
- Application Default Credentials generated [using gcloud](https://cloud.google.com/sdk/gcloud/reference/auth/application-default/login)
- [`kubectl`](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl) installed and configured with cluster access
- [current kubectl context](https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/#define-clusters-users-and-contexts) pointing to the relevant cluster
- python 3 and [pip](https://pypi.org/project/pip/) installed
- if running from source, python requirements installed: `pip install -r requirements.txt`

## Installation

This package is published to [PyPI](https://pypi.org/project/wi-analyzer/) and can be installed using `pip`:

```bash
pip install wi-analyzer
```

### Necessary project access

The script can be run by a user with the [`Viewer`](https://cloud.google.com/iam/docs/understanding-roles#basic-definitions) role in the project.

Alternatively, the user will need enough GKE cluster access to read Pods and ServiceAccounts, plus the following IAM permissions:

- container.clusters.get
- iam.serviceAccounts.get
- iam.serviceAccounts.getIamPolicy
- resourcemanager.projects.getIamPolicy

If the GSA is in a different GCP project than the GKE cluster, you'll need the last 3 permissions on that project instead.

## Using the tool

```bash
$ wi-analyzer --help
usage: wi-analyzer [-h] [-n NAMESPACE] [-d] pod

GKE Workload Identity Analyzer

positional arguments:
  pod                   Kubernetes Pod name to check

options:
  -h, --help            show this help message and exit
  -n NAMESPACE, --namespace NAMESPACE
                        Kubernetes Namespace to run in
  -p PROJECT, --project PROJECT
                        GCP Project holding the cluster
  -l LOCATION, --location LOCATION
                        The GCP location of the cluster
  -c CLUSTER, --cluster CLUSTER
                        The name of the cluster
  -d, --debug           Enable debug logging
```

Configure your current context to point at the cluster where the workload is running.
Either configure the relevant [namespace for the current context](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/#setting-the-namespace-preference) or pass the namespace name using the `-n` flag.

Pass a pod name to check - it can be part of a Deployment, Job, StatefulSet, etc, but it has to be running already.

## TODO

- Support [Fleet Workload Identity](https://cloud.google.com/anthos/fleet-management/docs/use-workload-identity) (GKE WI for Anthos)
