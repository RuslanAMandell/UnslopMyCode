import re
from typing import Set

# Migrations and .env files under a test or fixture tree describe test data, not
# production infrastructure. The rule engine already skips these paths; config
# detectors read files directly, so they need the same awareness.
_TEST_PATH_RE = re.compile(
    r"(?i)(^|/)(tests?|__tests__|spec|fixtures?|mocks?|examples?|samples?)/")


def is_test_path(rel: str) -> bool:
    return bool(_TEST_PATH_RE.search(rel))

from . import deps, gitignore, gitmeta, project, sqlrls, structure

ALL = [gitignore, sqlrls, deps, gitmeta, project, structure]


def detector_check_ids() -> Set[str]:
    out = set()
    for mod in ALL:
        out |= set(mod.EMITS)
    return out
