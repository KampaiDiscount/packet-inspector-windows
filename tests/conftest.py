"""Windows tests start in a genuinely private, newly-created temp directory."""
import os
import pytest


@pytest.fixture
def tmp_path(tmp_path_factory, request):
    parent = tmp_path_factory.mktemp(request.node.name[:40])
    if os.name == 'nt':
        from packet_audit.windows_security import create_private_directory
        private = parent / 'private'
        create_private_directory(private)
        return private
    return parent
