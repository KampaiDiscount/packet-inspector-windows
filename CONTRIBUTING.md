# Contributing

This repository contains the Windows adaptation of
[Packet Inspector](https://github.com/KampaiDiscount/packet-inspector), including
native Npcap capture, Windows launchers, evidence ACLs, and the shared analysis
engine. Use [SECURITY.md](SECURITY.md) for sensitive vulnerability reports.

## Development on Windows

Use 64-bit Python 3.11 or newer. From a source checkout, create an isolated
environment and install the project and development tools:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install . build 'setuptools>=77' wheel pytest==8.4.2
.\.venv\Scripts\python.exe -m pytest -o addopts= -q -rs
.\.venv\Scripts\python.exe -m compileall -q packet_audit tools
git diff --check
```

The Windows CI matrix runs Python 3.11 and 3.13. Platform/backend skips are
reported by pytest; passing the suite does not substitute for native driver or
physical-adapter validation. Keep regression cases synthetic and use fresh
temporary output directories. Do not add credentials, private captures, local
configuration, environments, or generated build files to a contribution.

For a documentation-only change, the existing documentation checks are:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_docs.py -o addopts= -q
```

## Building a deployment ZIP

```powershell
.\.venv\Scripts\python.exe tools\build_windows_release.py --output .\release-output
```

The builder requires the development tools above and refuses to replace an
existing ZIP. It includes source, launchers, the offline wheel, and checksum
manifests. See [WINDOWS.md](WINDOWS.md#building-from-source) for packaging details.
A Git checkout or GitHub source archive has no bundled wheel for `SETUP.cmd`;
ordinary users should start with the attached release deployment ZIP.

Native capture work also requires separately installed Npcap and Wireshark
dumpcap. Run live checks only on an explicitly chosen authorized adapter with
fresh evidence paths, following [WINDOWS-VALIDATION.md](WINDOWS-VALIDATION.md).
The opt-in live smoke helpers must not be treated as ordinary unit tests.

## Submitting a change

Keep the change focused and explain the problem, resulting behavior, and checks
performed. Preserve the distinction between observed traffic, detected
candidates, and proven security impact. For changes to capture, shutdown,
permissions, or detection, include a reproducible regression or clearly state
which deployment checks remain outstanding. Contributions follow the project's
[GPL-3.0-or-later license](LICENSE) and retain applicable third-party notices.
