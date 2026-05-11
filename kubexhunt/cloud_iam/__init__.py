"""Advanced cloud IAM attacks: privilege escalation and backdoor creation.

Turn stolen cloud credentials into persistent admin access through IAM manipulation.

Modules:
    aws_iam: AWS IAM privilege escalation paths and backdoor techniques
    gcp_iam: GCP service account escalation to org-level admin
    azure_iam: Azure App Registration and managed identity abuse
"""

from kubexhunt.cloud_iam.aws_iam import (
    AWSIAMAttacker,
    IAMEscalationPath,
)
from kubexhunt.cloud_iam.azure_iam import (
    AzureEscalationPath,
    AzureIAMAttacker,
)
from kubexhunt.cloud_iam.gcp_iam import (
    GCPEscalationPath,
    GCPIAMAttacker,
)

__all__ = [
    "IAMEscalationPath",
    "AWSIAMAttacker",
    "GCPEscalationPath",
    "GCPIAMAttacker",
    "AzureEscalationPath",
    "AzureIAMAttacker",
]
