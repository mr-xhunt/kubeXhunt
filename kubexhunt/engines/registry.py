"""Engine registry."""

from kubexhunt.engines.advanced import AdvancedEngine
from kubexhunt.engines.attack_chains import AttackChainsEngine
from kubexhunt.engines.azure import AzureEngine
from kubexhunt.engines.cloud import CloudMetadataEngine
from kubexhunt.engines.cluster_intel import ClusterIntelEngine
from kubexhunt.engines.cves import CVEEngine
from kubexhunt.engines.dos import DoSEngine
from kubexhunt.engines.eks import EKSEngine
from kubexhunt.engines.escape import EscapeEngine
from kubexhunt.engines.etcd import EtcdEngine
from kubexhunt.engines.gke import GKEEngine
from kubexhunt.engines.helm import HelmEngine
from kubexhunt.engines.kubelet import KubeletEngine
from kubexhunt.engines.misc import MiscEngine
from kubexhunt.engines.network import NetworkEngine
from kubexhunt.engines.node import NodeEngine
from kubexhunt.engines.openshift import OpenShiftEngine
from kubexhunt.engines.persistence import PersistenceEngine
from kubexhunt.engines.pod import PodReconEngine
from kubexhunt.engines.privesc import PrivEscEngine
from kubexhunt.engines.proc_harvest import ProcHarvestEngine
from kubexhunt.engines.rbac import RBACEngine
from kubexhunt.engines.runtime import RuntimeSecurityEngine
from kubexhunt.engines.secrets import SecretsEngine
from kubexhunt.engines.stealth import StealthEngine
from kubexhunt.engines.supply_chain import SupplyChainEngine

ENGINE_REGISTRY = {
    "pod": PodReconEngine(),
    "rbac": RBACEngine(),
    "network": NetworkEngine(),
    "escape": EscapeEngine(),
    "node": NodeEngine(),
    "privesc": PrivEscEngine(),
    "cloud": CloudMetadataEngine(),
    "eks": EKSEngine(),
    "gke": GKEEngine(),
    "runtime": RuntimeSecurityEngine(),
    "secrets": SecretsEngine(),
    "dos": DoSEngine(),
    "kubelet": KubeletEngine(),
    "etcd": EtcdEngine(),
    "helm": HelmEngine(),
    "proc_harvest": ProcHarvestEngine(),
    "azure": AzureEngine(),
    "openshift": OpenShiftEngine(),
    "advanced": AdvancedEngine(),
    "attack_chains": AttackChainsEngine(),
    "stealth": StealthEngine(),
    "misc": MiscEngine(),
    "supply_chain": SupplyChainEngine(),
    "persistence": PersistenceEngine(),
    "cves": CVEEngine(),
    "cluster_intel": ClusterIntelEngine(),
}
