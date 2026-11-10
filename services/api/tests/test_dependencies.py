import pytest
from kombu import Connection
from kombu.exceptions import OperationalError, VersionMismatch


def test_kombu_and_redis_versions_are_compatible():
    # Opening a channel runs kombu's redis-py version check before any network
    # I/O, so a closed port gives OperationalError when versions are fine and
    # VersionMismatch when a dependency bump broke the pair (as kombu 5.7.0 does
    # with redis 5.x — the worker crash-looped and scans couldn't be queued).
    with pytest.raises(OperationalError) as exc:
        Connection("redis://127.0.0.1:1/0", connect_timeout=1).default_channel
    assert not isinstance(exc.value, VersionMismatch)
