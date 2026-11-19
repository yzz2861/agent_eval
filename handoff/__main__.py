"""CLI for the file-based signing handoff.

Subcommands model the two sides of the handoff so they can run as
separate processes against a shared local directory:

    init         create store, issuer key and reviewer keys
    create-form  issue a new approval form
    sign         reviewer side: sign a form offline, drop into an inbox
    import       importer side: fold inbox submissions into the store
    renew        续签: issue successor form, revoke the old one
    revoke       作废 a form
    seal         封存: archive form + submissions, record the location
    demo         full two-reviewer cross-process simulation
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from handoff.fakesigner import FAKE_SCHEME, FakeKey, FakeSigner
from handoff.service import HandoffService
from handoff.store import FormStore

REVIEWERS = ("alice", "bob")


def _keys_dir(root: Path) -> Path:
    return root / "keys"


def _issuer_key_path(root: Path) -> Path:
    return _keys_dir(root) / "issuer.json"


def _reviewer_key_path(root: Path, name: str) -> Path:
    return _keys_dir(root) / f"reviewer-{name}.json"


def _load_fake_key(path: Path) -> FakeKey:
    data = json.loads(path.read_text())
    keyid = FakeKey.generate(data["keyval"]["public"]).keyid
    return FakeKey.from_dict(keyid, dict(data))


def _open_service(root: Path) -> HandoffService:
    store = FormStore(root)
    issuer = _load_fake_key(_issuer_key_path(root))
    reviewers = {}
    for name in REVIEWERS:
        path = _reviewer_key_path(root, name)
        if path.exists():
            key = _load_fake_key(path)
            reviewers[key.keyid] = key
    return HandoffService(store, issuer, reviewers)


def _signer_for(key: FakeKey) -> FakeSigner:
    return FakeSigner.from_priv_key_uri(
        f"{FAKE_SCHEME}:{key.keyval['public']}", key
    )


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root)
    store = FormStore(root)
    issuer = FakeKey.generate()
    store.write_json(_issuer_key_path(root), issuer.to_dict())
    for name in REVIEWERS:
        key = FakeKey.generate()
        store.write_json(_reviewer_key_path(root, name), key.to_dict())
    print(f"initialized store at {root.resolve()}")
    print(f"issuer keyid: {issuer.keyid}")
    return 0


def cmd_create_form(args: argparse.Namespace) -> int:
    root = Path(args.root)
    service = _open_service(root)
    payload = Path(args.payload).read_bytes()
    issuer = _signer_for(_load_fake_key(_issuer_key_path(root)))
    form = service.create_form(
        payload, sorted(service.reviewer_keys), args.policy_rev, issuer
    )
    print(form.form_id)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Reviewer side: runs offline, only needs own key + the form file."""
    root = Path(args.root)
    store = FormStore(root)
    key = _load_fake_key(_reviewer_key_path(root, args.reviewer))
    form = store.load_form(args.form).form
    submission = HandoffService.build_submission(form, _signer_for(key))
    inbox = Path(args.out)
    inbox.mkdir(parents=True, exist_ok=True)
    out = inbox / f"{form.form_id}-{args.reviewer}.json"
    store.write_json(out, submission)
    print(f"{args.reviewer} signed form {form.form_id} -> {out}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    service = _open_service(Path(args.root))
    exit_code = 0
    for inbox in args.inbox:
        for result in service.import_inbox(inbox):
            status = "ACCEPTED" if result.accepted else "REJECTED"
            if result.duplicate:
                status = "DUPLICATE"
            print(
                f"{status} form={result.form_id} "
                f"reviewer={result.reviewer}: {result.reason}"
            )
            if not result.accepted:
                exit_code = 1
    return exit_code


def cmd_renew(args: argparse.Namespace) -> int:
    root = Path(args.root)
    service = _open_service(root)
    payload = Path(args.payload).read_bytes()
    issuer = _signer_for(_load_fake_key(_issuer_key_path(root)))
    form = service.renew_form(
        args.form, payload, sorted(service.reviewer_keys),
        args.policy_rev, issuer,
    )
    print(form.form_id)
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    service = _open_service(Path(args.root))
    service.revoke_form(args.form)
    print(f"revoked {args.form}")
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    service = _open_service(Path(args.root))
    manifest = service.seal_form(args.form)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def _run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "handoff", *argv],
        capture_output=True,
        text=True,
        **kwargs,
    )


def cmd_demo(args: argparse.Namespace) -> int:
    """Simulate two reviewers submitting across processes via local dirs."""
    root = Path(args.root)

    def run(argv: list[str]) -> subprocess.CompletedProcess:
        proc = _run(["--root", str(root), *argv])
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        return proc

    print("== init ==")
    print(run(["init"]).stdout.strip())

    payload_file = root / "payload.bin"
    payload_file.write_bytes(b"release-artifact-v1\n")

    print("== create form rev1 ==")
    rev1 = run(
        ["create-form", "--payload", str(payload_file), "--policy-rev", "1"]
    ).stdout.strip()
    print(f"form rev1: {rev1}")

    print("== reviewers sign offline in separate processes ==")
    for name in REVIEWERS:
        inbox = root / "inbox" / name
        proc = run(
            ["sign", "--form", rev1, "--reviewer", name, "--out", str(inbox)]
        )
        print(proc.stdout.strip())

    print("== import both inboxes ==")
    proc = run(
        ["import", "--inbox", str(root / "inbox" / "alice"),
         "--inbox", str(root / "inbox" / "bob")]
    )
    print(proc.stdout.strip())

    print("== renew: rev2 created, rev1 revoked ==")
    rev2 = run(
        ["renew", "--form", rev1, "--payload", str(payload_file),
         "--policy-rev", "2"]
    ).stdout.strip()
    print(f"form rev2: {rev2}")

    print("== acceptance: old form's valid signature comes back ==")
    stale_inbox = root / "inbox" / "late"
    stale_inbox.mkdir(parents=True, exist_ok=True)
    # take alice's already-imported rev1 submission and resubmit it
    alice_sub = next((root / "submissions" / rev1).glob("*.json"))
    (stale_inbox / alice_sub.name).write_text(alice_sub.read_text())
    proc = _run(["--root", str(root), "import", "--inbox", str(stale_inbox)])
    print(proc.stdout.strip())

    print("== reviewers sign rev2, import, then seal ==")
    for name in REVIEWERS:
        inbox = root / "inbox2" / name
        run(["sign", "--form", rev2, "--reviewer", name, "--out", str(inbox)])
    proc = run(
        ["import", "--inbox", str(root / "inbox2" / "alice"),
         "--inbox", str(root / "inbox2" / "bob")]
    )
    print(proc.stdout.strip())
    proc = run(["seal", "--form", rev2])
    print(proc.stdout.strip())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="handoff")
    parser.add_argument("--root", default="handoff-store")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")

    p = sub.add_parser("create-form")
    p.add_argument("--payload", required=True)
    p.add_argument("--policy-rev", type=int, required=True)

    p = sub.add_parser("sign")
    p.add_argument("--form", required=True)
    p.add_argument("--reviewer", required=True, choices=REVIEWERS)
    p.add_argument("--out", required=True)

    p = sub.add_parser("import")
    p.add_argument("--inbox", action="append", required=True)

    p = sub.add_parser("renew")
    p.add_argument("--form", required=True)
    p.add_argument("--payload", required=True)
    p.add_argument("--policy-rev", type=int, required=True)

    p = sub.add_parser("revoke")
    p.add_argument("--form", required=True)

    p = sub.add_parser("seal")
    p.add_argument("--form", required=True)

    sub.add_parser("demo")

    args = parser.parse_args(argv)
    handler = {
        "init": cmd_init,
        "create-form": cmd_create_form,
        "sign": cmd_sign,
        "import": cmd_import,
        "renew": cmd_renew,
        "revoke": cmd_revoke,
        "seal": cmd_seal,
        "demo": cmd_demo,
    }[args.cmd]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
