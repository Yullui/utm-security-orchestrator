import os
import tempfile
from generate_sbom import generate_sbom


def test_generate_sbom():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write('requests==2.28.0\n# comment\npytest')
        out = path + '.sbom.json'
        generate_sbom(path, out)
        assert os.path.exists(out)
        with open(out, 'r', encoding='utf-8') as f:
            data = f.read()
            assert 'requests' in data
    finally:
        os.remove(path)
        if os.path.exists(out):
            os.remove(out)
