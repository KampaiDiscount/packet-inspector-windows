"""Build a source-inclusive Windows ZIP from a clean, allowlisted staging tree."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    label = 'Packet-Inspector-Windows-0.1.4-win1'
    archive = output / f'{label}.zip'
    if archive.exists():
        raise ValueError('Refusing to overwrite an existing release archive')
    roots = ['packet_audit', 'config', 'scripts', 'systemd', 'tests', 'tools', 'windows']
    extensions = {'.py', '.toml', '.sh', '.service', '.ps1'}
    with tempfile.TemporaryDirectory(prefix='packet-inspector-win-build-') as temporary:
        stage = Path(temporary) / label
        stage.mkdir()
        for path in source.iterdir():
            if path.is_file() and (path.suffix in {'.md', '.cmd', '.toml'} or path.name in {'LICENSE', 'MANIFEST.in', '.gitignore', '.gitattributes'}):
                shutil.copy2(path, stage / path.name)
        for root in roots:
            for path in (source / root).rglob('*'):
                if path.is_file() and path.suffix in extensions and '__pycache__' not in path.parts:
                    destination = stage / path.relative_to(source)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
        # cmd.exe and Windows PowerShell 5.1 get conventional CRLF scripts.
        for path in list(stage.glob('*.cmd')) + list((stage / 'windows').glob('*.ps1')):
            path.write_bytes(path.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
        subprocess.run([sys.executable, '-m', 'build', '--no-isolation', '--outdir', str(stage / 'dist'), str(stage)], check=True)
        # Build intermediates are not release contents.
        files = sorted(path for path in stage.rglob('*') if path.is_file()
                       and 'build' not in path.relative_to(stage).parts
                       and not any(part.endswith('.egg-info') for part in path.relative_to(stage).parts))
        checksums = stage / 'SHA256SUMS.txt'
        checksums.write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(stage).as_posix()}\n' for path in files), encoding='utf-8')
        files.append(checksums)
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            for path in files:
                bundle.write(path, f'{label}/{path.relative_to(stage).as_posix()}')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / f'{archive.name}.sha256').write_text(f'{digest}  {archive.name}\n', encoding='utf-8')
    print(f'{archive}\nSHA256 {digest}')


if __name__ == '__main__':
    main()
