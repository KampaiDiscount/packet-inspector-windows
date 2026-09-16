import os
import subprocess
from pathlib import Path
import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Native Windows DACL tests')


def test_new_directory_and_inherited_files_are_private(tmp_path):
    from packet_audit.windows_security import create_private_directory, private_acl_error
    target = tmp_path / 'evidence'
    create_private_directory(target)
    assert private_acl_error(target) is None
    file = target / 'synthetic.jsonl'
    file.write_text('{}\n')
    assert private_acl_error(file) is None
    with file.open('rb') as handle:
        assert private_acl_error(file, fd=handle.fileno()) is None


def test_shared_existing_directory_is_refused_without_acl_rewrite(tmp_path):
    from packet_audit.windows_security import private_acl_error
    from packet_audit.writer import prepare_private_directory
    shared = tmp_path / 'shared'
    shared.mkdir()
    # Explicitly alter only this newly-created synthetic test directory.
    subprocess.run(['icacls.exe', str(shared), '/grant', '*S-1-1-0:(OI)(CI)R'], check=True, capture_output=True)
    before = subprocess.check_output(['icacls.exe', str(shared)])
    assert private_acl_error(shared)
    with pytest.raises(PermissionError):
        prepare_private_directory(shared)
    assert subprocess.check_output(['icacls.exe', str(shared)]) == before


def test_shared_file_and_hardlink_are_refused(tmp_path):
    from packet_audit.writer import _restricted_text_append
    target = tmp_path / 'shared.jsonl'
    target.write_text('{}\n')
    subprocess.run(['icacls.exe', str(target), '/grant', '*S-1-1-0:R'], check=True, capture_output=True)
    with pytest.raises(PermissionError):
        _restricted_text_append(target)
    original = tmp_path / 'original.jsonl'
    original.write_text('{}\n')
    linked = tmp_path / 'linked.jsonl'
    os.link(original, linked)
    with pytest.raises(PermissionError):
        _restricted_text_append(linked)


def test_device_paths_and_alternate_streams_are_rejected(tmp_path):
    from packet_audit.windows_security import checked_local_path
    for path in [r'\\server\share\evidence', str(tmp_path / 'file:stream')]:
        with pytest.raises(PermissionError):
            checked_local_path(path)


def test_junction_ancestor_is_rejected(tmp_path):
    from packet_audit.windows_security import checked_local_path
    target, link = tmp_path / 'target', tmp_path / 'junction'
    target.mkdir()
    result = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)], capture_output=True)
    if result.returncode:
        pytest.skip('junction creation unavailable')
    try:
        with pytest.raises(PermissionError):
            checked_local_path(link / 'child.jsonl')
    finally:
        # Remove only the junction itself, never recurse into its target.
        os.rmdir(link)
