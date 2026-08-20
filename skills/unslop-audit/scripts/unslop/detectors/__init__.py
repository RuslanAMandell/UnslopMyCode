from typing import Set

from . import deps, gitignore, gitmeta, project, sqlrls, structure

ALL = [gitignore, sqlrls, deps, gitmeta, project, structure]


def detector_check_ids() -> Set[str]:
    out = set()
    for mod in ALL:
        out |= set(mod.EMITS)
    return out
