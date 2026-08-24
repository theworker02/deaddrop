# Compatibility

* **Stable DDP versions:** backward compatibility required on the wire.
* **Experimental extensions:** compatibility not guaranteed.
* **Storage migrations:** MUST support upgrade from the previous stable schema (schema 2 in this tree).
* **Application version** MUST NOT be used as a protocol version.

Tagging `v*.*.*` publishes GitHub Release archives with SHA-256 checksums, an SPDX SBOM, and Sigstore keyless signatures. A Homebrew formula and winget manifests are attached to the same release (not yet in homebrew-core / winget-pkgs). Protocol experimental features MUST NOT silently become stable requirements.
