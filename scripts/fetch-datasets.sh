#!/usr/bin/env bash
# Downloads the public benchmark datasets into testdata/datasets/ (gitignored).
# Run from the repo root:  bash scripts/fetch-datasets.sh
#
# Every archive is verified against a pinned SHA-256 so benchmark numbers in
# BASELINE.md are reproducible against byte-identical inputs.
set -euo pipefail

DEST="testdata/datasets"
CACHE="$DEST/.cache"
mkdir -p "$CACHE"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# fetch <url> <cache-file> <expected-sha256>
fetch() {
  local url="$1" out="$CACHE/$2" want="$3"
  if [ ! -f "$out" ]; then
    echo "→ downloading $2"
    curl -fsSL --retry 3 -o "$out.part" "$url"
    mv "$out.part" "$out"
  fi
  local got
  got="$(sha256 "$out")"
  if [ "$got" != "$want" ]; then
    echo "✗ checksum mismatch for $2: got $got want $want" >&2
    exit 1
  fi
}

ZENODO="https://zenodo.org/api/records/8196385/files"
MORDOR="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

# 1. LogHub OpenSSH — real sshd log from a lab server under live brute-force attack (655k lines).
fetch "$ZENODO/SSH.tar.gz/content" SSH.tar.gz "296610a35773f58b7c295e5407fc5ccdf48beb3c544fc14a6309addf904a2712"
mkdir -p "$DEST/loghub-ssh"
tar -xzf "$CACHE/SSH.tar.gz" -C "$DEST/loghub-ssh"

# 2. LogHub Linux — real /var/log/messages from a Linux host (mostly benign system activity).
fetch "$ZENODO/Linux.tar.gz/content" Linux.tar.gz "7e1f820d8d45ae086032e515d9ce8d079a102a9b37dcff5b41a8e60b1f857820"
mkdir -p "$DEST/loghub-linux"
tar -xzf "$CACHE/Linux.tar.gz" -C "$DEST/loghub-linux"

# 3. OTRF Security-Datasets (Mordor) — Windows Security/Sysmon events exported as JSON lines.
#    Used in place of raw .evtx files (EVTX binary parsing is out of Phase 1 scope).
fetch "$MORDOR/credential_access/host/empire_mimikatz_logonpasswords.zip" mordor_mimikatz.zip "bb4c057b62d781be5426e011872ba1a15070c07afbb24848a14458f4b22b06fb"
fetch "$MORDOR/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip" mordor_psexec.zip "8f40e7fc86bbbf31ebd50b3ba537cf0f4378392ae3e74de84bee00aeb0de1fa5"
mkdir -p "$DEST/mordor"
for z in mordor_mimikatz.zip mordor_psexec.zip; do
  unzip -o -q "$CACHE/$z" -d "$DEST/mordor"
done

echo "✓ datasets ready under $DEST/"
find "$DEST" -path "$DEST/.cache" -prune -o -type f -print
