from uuid import uuid1, uuid4

import pytest

from waygate.authority import AuthorityError, INSTALLATION_PREFIX, MARKER, managed_installation_id


def config(installation_id):
    return f"{MARKER}\n{INSTALLATION_PREFIX}{installation_id}\n[Interface]\n".encode()


def test_exact_markers_identify_installation():
    installation_id = uuid4()
    assert managed_installation_id(config(installation_id)) == installation_id

@pytest.mark.parametrize("content", [b"[Interface]\n", f"{MARKER}\n{INSTALLATION_PREFIX}not-a-uuid\n".encode(), f"{MARKER}\n{INSTALLATION_PREFIX}{uuid4()}\n{MARKER}\n".encode()])
def test_malformed_or_duplicate_ownership_is_rejected(content):
    with pytest.raises(AuthorityError):
        managed_installation_id(content)


def test_non_v4_installation_identity_is_rejected():
    with pytest.raises(AuthorityError):
        managed_installation_id(config(uuid1()))


@pytest.mark.parametrize("line", ["# Installation-ID:bad", "# Installation-ID:" + str(uuid4()), "# Managed by waygate; EDITED"])
def test_marker_stems_outside_header_are_rejected(line):
    with pytest.raises(AuthorityError):
        managed_installation_id(config(uuid4()) + (line + "\n").encode())
