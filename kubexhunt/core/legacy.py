"""Legacy compatibility loader for the existing monolithic script."""

from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache
from types import ModuleType

from kubexhunt.core.utils import repo_root


@lru_cache(maxsize=1)
def load_legacy_module() -> ModuleType:
    """Load the existing `kubexhunt.py` script as a module without changing it."""

    legacy_path = repo_root() / "kubexhunt.py"
    spec = importlib.util.spec_from_file_location("kubexhunt_legacy", legacy_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load legacy module from {legacy_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def legacy_main() -> int:
    """Execute the legacy main entrypoint."""

    module = load_legacy_module()
    module.main()
    return 0
