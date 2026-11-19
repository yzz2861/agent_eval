"""Crash-safe file storage for the handoff workflow.

Layout under the store root::

    forms/<form_id>.json          signed approval forms
    submissions/<form_id>/<keyid>.json
    journal/<op>-<id>.json        in-flight multi-step operations
    archive/<form_id>/            sealed material
    keys/                         issuer / reviewer key files (demo setup)

Every write is atomic: data goes to a ``*.tmp-*`` sibling, is fsynced,
then ``os.replace``d onto the target, followed by a directory fsync.
Multi-step operations (renew, seal) first persist a journal record;
:meth:`FormStore.recover` replays unfinished records and removes stale
temp files, so a crash anywhere mid-write leaves a consistent state.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any, Callable

from handoff.form import SignedForm


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class FormStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        for sub in ("forms", "submissions", "journal", "archive", "keys"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    def atomic_write(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(
            f"{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
        )
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)

    def write_json(self, path: Path, obj: Any) -> None:
        self.atomic_write(
            path, json.dumps(obj, indent=2, sort_keys=True).encode("utf-8")
        )

    @staticmethod
    def read_json(path: Path) -> Any:
        with open(path, "rb") as f:
            return json.load(f)

    def journal_begin(self, op: str, payload: dict[str, Any]) -> Path:
        record = {"op": op, "payload": payload, "done": False}
        path = self.root / "journal" / f"{op}-{secrets.token_hex(8)}.json"
        self.write_json(path, record)
        return path

    def journal_done(self, path: Path) -> None:
        record = self.read_json(path)
        record["done"] = True
        self.write_json(path, record)

    def pending_journals(self) -> list[tuple[Path, dict[str, Any]]]:
        pending = []
        for path in sorted((self.root / "journal").glob("*.json")):
            record = self.read_json(path)
            if not record.get("done"):
                pending.append((path, record))
        return pending

    def recover(
        self, handlers: dict[str, Callable[[dict[str, Any]], None]]
    ) -> list[str]:
        """Replay unfinished journal ops and remove stale temp files.

        Handlers must be idempotent: their individual steps may have
        partially completed before a crash.
        """
        recovered = []
        for tmp in self.root.rglob("*.tmp-*"):
            tmp.unlink()
        for path, record in self.pending_journals():
            handler = handlers.get(record["op"])
            if handler is None:
                continue
            handler(record["payload"])
            self.journal_done(path)
            recovered.append(record["op"])
        return recovered

    def form_path(self, form_id: str) -> Path:
        return self.root / "forms" / f"{form_id}.json"

    def save_form(self, signed_form: SignedForm) -> None:
        self.write_json(
            self.form_path(signed_form.form.form_id), signed_form.to_dict()
        )

    def load_form(self, form_id: str) -> SignedForm:
        return SignedForm.from_dict(self.read_json(self.form_path(form_id)))

    def has_form(self, form_id: str) -> bool:
        return self.form_path(form_id).exists()

    def list_forms(self) -> list[str]:
        return sorted(p.stem for p in (self.root / "forms").glob("*.json"))

    def submission_path(self, form_id: str, keyid: str) -> Path:
        return self.root / "submissions" / form_id / f"{keyid}.json"

    def load_submission(self, form_id: str, keyid: str) -> dict[str, Any]:
        return self.read_json(self.submission_path(form_id, keyid))

    def has_submission(self, form_id: str, keyid: str) -> bool:
        return self.submission_path(form_id, keyid).exists()

    def save_submission(self, form_id: str, submission: dict[str, Any]) -> None:
        self.write_json(
            self.submission_path(form_id, submission["reviewer"]), submission
        )

    def list_submissions(self, form_id: str) -> list[dict[str, Any]]:
        directory = self.root / "submissions" / form_id
        if not directory.is_dir():
            return []
        return [self.read_json(p) for p in sorted(directory.glob("*.json"))]
