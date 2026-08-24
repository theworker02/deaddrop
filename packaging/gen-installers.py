#!/usr/bin/env python3
"""Generate Homebrew formula and winget manifests from release archives."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find(dist: pathlib.Path, suffix: str) -> pathlib.Path:
    matches = sorted(dist.glob(f"*{suffix}"))
    if not matches:
        raise SystemExit(f"missing archive matching *{suffix} in {dist}")
    return matches[0]


def brew_formula(version: str, urls: dict[str, tuple[str, str]]) -> str:
    def block(key: str) -> str:
        url, sha = urls[key]
        return f'      url "{url}"\n      sha256 "{sha}"'

    return f'''class Deaddrop < Formula
  desc "Encrypted delay-tolerant networking (DDP/2)"
  homepage "https://github.com/theworker02/deaddrop"
  version "{version}"
  license "MIT"

  on_macos do
    on_arm do
{block("darwin-arm")}
    end
    on_intel do
{block("darwin-amd")}
    end
  end

  on_linux do
    on_arm do
{block("linux-arm")}
    end
    on_intel do
{block("linux-amd")}
    end
  end

  def install
    bin.install "dd", "dd-daemon", "dd-relay", "dd-sim"
  end

  service do
    run [opt_bin/"dd-daemon", "--data-dir", var/"deaddrop", "--listen", "0.0.0.0:7947"]
    keep_alive true
    working_dir var/"deaddrop"
    log_path var/"log/deaddrop.log"
    error_log_path var/"log/deaddrop.log"
  end

  test do
    assert_match "DDP", shell_output("#{{bin}}/dd --version")
  end
end
'''


def winget(version: str, url: str, sha: str) -> tuple[str, str, str]:
    ident = "theworker02.DeadDrop"
    version_yaml = f"""PackageIdentifier: {ident}
PackageVersion: {version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.6.0
"""
    locale = f"""PackageIdentifier: {ident}
PackageVersion: {version}
PackageLocale: en-US
Publisher: theworker02
PackageName: DeadDrop
License: MIT OR Apache-2.0
ShortDescription: Encrypted delay-tolerant networking for computers that are not always online together.
PackageUrl: https://github.com/theworker02/deaddrop
ManifestType: defaultLocale
ManifestVersion: 1.6.0
"""
    installer = f"""PackageIdentifier: {ident}
PackageVersion: {version}
InstallerLocale: en-US
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: dd.exe
    PortableCommandAlias: dd
  - RelativeFilePath: dd-daemon.exe
    PortableCommandAlias: dd-daemon
  - RelativeFilePath: dd-relay.exe
    PortableCommandAlias: dd-relay
  - RelativeFilePath: dd-sim.exe
    PortableCommandAlias: dd-sim
UpgradeBehavior: uninstallPrevious
Installers:
  - Architecture: x64
    InstallerUrl: {url}
    InstallerSha256: {sha}
    InstallerType: zip
ManifestType: installer
ManifestVersion: 1.6.0
"""
    return version_yaml, locale, installer


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version", required=True)
    p.add_argument("--dist", required=True, type=pathlib.Path)
    p.add_argument("--out", required=True, type=pathlib.Path)
    args = p.parse_args()
    tag = f"v{args.version}"
    base = f"https://github.com/theworker02/deaddrop/releases/download/{tag}"
    keys = {
        "linux-amd": "x86_64-unknown-linux-gnu.tar.gz",
        "linux-arm": "aarch64-unknown-linux-gnu.tar.gz",
        "darwin-amd": "x86_64-apple-darwin.tar.gz",
        "darwin-arm": "aarch64-apple-darwin.tar.gz",
        "win-amd": "x86_64-pc-windows-msvc.zip",
    }
    urls: dict[str, tuple[str, str]] = {}
    for key, suffix in keys.items():
        path = find(args.dist, suffix)
        sha = sha256_file(path)
        urls[key] = (f"{base}/{path.name}", sha)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "deaddrop.rb").write_text(
        brew_formula(args.version, urls), encoding="utf-8"
    )
    ver, loc, inst = winget(args.version, urls["win-amd"][0], urls["win-amd"][1])
    winget_dir = args.out / "winget"
    winget_dir.mkdir(exist_ok=True)
    (winget_dir / "theworker02.DeadDrop.yaml").write_text(ver, encoding="utf-8")
    (winget_dir / "theworker02.DeadDrop.locale.en-US.yaml").write_text(
        loc, encoding="utf-8"
    )
    (winget_dir / "theworker02.DeadDrop.installer.yaml").write_text(
        inst, encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
