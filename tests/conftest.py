import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tests.fakedevice import build  # noqa: E402

DISPATCH = ROOT / "tests" / "fakebin" / "dispatch"


@pytest.fixture(scope="session")
def dispatch() -> Path:
    return DISPATCH


@pytest.fixture
def device(tmp_path, dispatch):
    def _make(name: str):
        return build(name, tmp_path, dispatch)

    return _make
