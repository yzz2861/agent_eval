"""Generate the incident-review fixtures: JKS backups and collection manifests.

Two small cases are produced under fixtures/:

* case_scope_gap -- every collection declared only part of the mandated
  aliases, leaving a scope gap around the alias that actually held the old
  certificate (which was also renamed between the two backups).
* case_full_inventory -- every collection declared the full mandated
  alias list, giving a complete inventory of each backup.

Requires openssl on PATH. Keystores are written with pyjks itself
(TrustedCertEntry + KeyStore.saves), so no keytool is needed. Re-running
regenerates fresh keys/certificates and rewrites the manifests with the
new fingerprints.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jks

HERE = Path(__file__).resolve().parent
FIXTURES_DIR = HERE / "fixtures"
STORE_PASSWORD = "changeit"

MANDATED_ALIASES = ["edge-gateway", "code-signing", "legacy-root", "spare"]

CERT_SUBJECTS = {
    "legacy": "/CN=legacy.internal/O=Example Incident Review",
    "edge": "/CN=edge.example.internal/O=Example Incident Review",
    "signing": "/CN=signing.example.internal/O=Example Incident Review",
    "spare": "/CN=spare.example.internal/O=Example Incident Review",
}

CASES = {
    "case_scope_gap": {
        "summary": "两次采集均只覆盖规定别名的一部分，留有范围缺口",
        "target_cert": "legacy",
        "backups": [
            {
                "id": "b1",
                "file": "backup_t1.jks",
                "taken_at": "2024-03-01T02:00:00Z",
                "entries": {
                    "edge-gateway": "edge",
                    "code-signing": "signing",
                    "legacy-root": "legacy",
                    "spare": "spare",
                },
            },
            {
                "id": "b2",
                "file": "backup_t2.jks",
                "taken_at": "2024-09-01T02:00:00Z",
                "entries": {
                    "edge-gateway": "edge",
                    "code-signing": "signing",
                    # same certificate, alias renamed between the two backups
                    "retired-root-2023": "legacy",
                    "spare": "spare",
                },
            },
        ],
        "collections": [
            {
                "id": "c1",
                "at": "2024-03-01T03:00:00Z",
                "backup": "b1",
                "declared_scope": ["edge-gateway", "code-signing"],
            },
            {
                "id": "c2",
                "at": "2024-09-01T03:00:00Z",
                "backup": "b2",
                "declared_scope": ["edge-gateway", "code-signing", "spare"],
            },
        ],
    },
    "case_full_inventory": {
        "summary": "每次采集均为覆盖全部规定别名的完整盘点单",
        "target_cert": "legacy",
        "backups": [
            {
                "id": "b0",
                "file": "backup_t0.jks",
                "taken_at": "2023-06-01T02:00:00Z",
                "entries": {
                    "edge-gateway": "edge",
                    "code-signing": "signing",
                    "legacy-root": "legacy",
                    "spare": "spare",
                },
            },
            {
                "id": "b1",
                "file": "backup_t1.jks",
                "taken_at": "2024-03-01T02:00:00Z",
                "entries": {
                    "edge-gateway": "edge",
                    "code-signing": "signing",
                    "spare": "spare",
                },
            },
            {
                "id": "b2",
                "file": "backup_t2.jks",
                "taken_at": "2024-09-01T02:00:00Z",
                "entries": {
                    "edge-gateway": "edge",
                    "code-signing": "signing",
                    "spare": "spare",
                },
            },
        ],
        "collections": [
            {
                "id": "c0",
                "at": "2023-06-01T03:00:00Z",
                "backup": "b0",
                "declared_scope": list(MANDATED_ALIASES),
            },
            {
                "id": "c1",
                "at": "2024-03-01T03:00:00Z",
                "backup": "b1",
                "declared_scope": list(MANDATED_ALIASES),
            },
            {
                "id": "c2",
                "at": "2024-09-01T03:00:00Z",
                "backup": "b2",
                "declared_scope": list(MANDATED_ALIASES),
            },
        ],
    },
}


def run(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def make_cert(workdir, name, subject):
    der = workdir / (name + ".der")
    key = workdir / (name + ".key")
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(der), "-outform", "DER",
        "-days", "3650", "-nodes", "-sha256", "-subj", subject,
    ])
    return der


def build_keystore(path, entries, cert_files):
    store_entries = [
        jks.TrustedCertEntry.new(alias, cert_files[cert_name].read_bytes())
        for alias, cert_name in entries.items()
    ]
    store = jks.KeyStore.new("jks", store_entries)
    path.write_bytes(store.saves(STORE_PASSWORD))


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def build_case(case_name, spec):
    case_dir = FIXTURES_DIR / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    certs_dir = case_dir / "certs"
    certs_dir.mkdir(parents=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        cert_names = {spec["target_cert"]}
        for backup in spec["backups"]:
            cert_names.update(backup["entries"].values())
        cert_files = {}
        cert_fps = {}
        for name in sorted(cert_names):
            der = make_cert(tmpdir, name, CERT_SUBJECTS[name])
            shutil.copy(der, certs_dir / (name + ".der"))
            cert_files[name] = der
            cert_fps[name] = sha256_hex(der.read_bytes())

        for backup in spec["backups"]:
            build_keystore(case_dir / backup["file"], backup["entries"], cert_files)

    manifest = {
        "case": case_name,
        "summary": spec["summary"],
        "store_password": STORE_PASSWORD,
        "mandated_aliases": MANDATED_ALIASES,
        "target_certificate": {
            "label": "旧证书 " + CERT_SUBJECTS[spec["target_cert"]].split("/")[1][3:],
            "cert": spec["target_cert"],
            "sha256": cert_fps[spec["target_cert"]],
        },
        "certificates": {
            name: {"sha256": fp, "file": "certs/" + name + ".der"}
            for name, fp in sorted(cert_fps.items())
        },
        "backups": [
            {"id": b["id"], "file": b["file"], "taken_at": b["taken_at"]}
            for b in spec["backups"]
        ],
        "collections": [],
    }

    backups_by_id = {b["id"]: b for b in spec["backups"]}
    for col in spec["collections"]:
        entries = backups_by_id[col["backup"]]["entries"]
        recorded = [
            {"alias": alias, "sha256": cert_fps[cert_name]}
            for alias, cert_name in sorted(entries.items())
            if alias in col["declared_scope"]
        ]
        manifest["collections"].append({
            "id": col["id"],
            "at": col["at"],
            "backup": col["backup"],
            "declared_scope": col["declared_scope"],
            "recorded_observations": recorded,
        })

    manifest_path = case_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print("built %s: %s" % (case_name, manifest_path))


def main():
    FIXTURES_DIR.mkdir(exist_ok=True)
    for case_name, spec in CASES.items():
        build_case(case_name, spec)


if __name__ == "__main__":
    main()
