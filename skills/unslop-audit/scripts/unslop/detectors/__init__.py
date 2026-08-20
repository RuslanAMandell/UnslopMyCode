from typing import Set

from ..walker import is_test_path   # noqa: F401  (re-exported for detectors)


from . import deps, gitignore, gitmeta, project, sqlrls, structure

ALL = [gitignore, sqlrls, deps, gitmeta, project, structure]


def detector_check_ids() -> Set[str]:
    out = set()
    for mod in ALL:
        out |= set(mod.EMITS)
    return out
