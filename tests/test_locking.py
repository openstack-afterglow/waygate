from pathlib import Path

import pytest

from waygate.db import InstanceAlreadyRunning, InstanceLease


def test_second_instance_lease_fails_without_releasing_first(tmp_path: Path):
    first = InstanceLease(tmp_path / "instance.lock")
    second = InstanceLease(tmp_path / "instance.lock")
    first.acquire()
    try:
        with pytest.raises(InstanceAlreadyRunning, match="instance_already_running"):
            second.acquire()
    finally:
        first.release()
