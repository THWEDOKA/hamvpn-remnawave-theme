"""Build-time downloads from upstream releases, verified before extraction."""

import gzip
import hashlib
import io
import platform
import urllib.request
import zipfile
from pathlib import Path

ASSETS = (
    (
        "xray",
        "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-linux-64.zip",
        "8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40",
    ),
    (
        "mihomo",
        "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.24/mihomo-linux-amd64-v1.19.24.gz",
        "a1aca7b07037d06d0093320386c54d86e4ed9979394a20034f3e86013a7ae6e7",
    ),
)


def main():
    if platform.machine() != "x86_64":
        raise RuntimeError("Probe cores are pinned for linux/amd64")
    destination = Path("/probe-cores")
    destination.mkdir()
    for name, url, expected in ASSETS:
        with urllib.request.urlopen(url, timeout=120) as response:
            archive = response.read()
        if hashlib.sha256(archive).hexdigest() != expected:
            raise RuntimeError("Upstream probe archive checksum mismatch")
        binary = (
            zipfile.ZipFile(io.BytesIO(archive)).read("xray")
            if name == "xray"
            else gzip.decompress(archive)
        )
        path = destination / name
        path.write_bytes(binary)
        path.chmod(0o755)


if __name__ == "__main__":
    main()
