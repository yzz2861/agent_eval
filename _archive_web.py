"""Optional HTTP adapter for the archive settlement engine."""

from __future__ import absolute_import

import json

import archive_exchange as core


def create_app(manifest=None, exchange=None):
    try:
        from flask import Flask, jsonify, request
    except ImportError:  # pragma: no cover - Flask is optional
        return _MissingFlaskApp()

    app = Flask(__name__)
    app.config["ARCHIVE_EXCHANGE"] = exchange or core.ArchiveExchange(manifest or {})

    def _exchange(payload=None):
        current = app.config["ARCHIVE_EXCHANGE"]
        if payload and isinstance(payload, dict):
            manifest_value = payload.get("manifest") or payload.get("approval_manifest")
            if manifest_value and not current.manifest:
                current = core.ArchiveExchange(manifest_value)
                app.config["ARCHIVE_EXCHANGE"] = current
        return current

    def _payload():
        if request.files:
            documents = []
            for key, storage in request.files.items():
                raw = storage.read()
                documents.append(
                    {
                        "document_id": storage.filename,
                        "filename": storage.filename,
                        "xml": raw,
                    }
                )
            form = request.form.to_dict(flat=True)
            form["documents"] = documents
            return form
        payload = request.get_json(silent=True)
        if payload is None:
            raw = request.data or b""
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                payload = {"xml": raw}
        return payload

    def _requests_from_payload(payload):
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return payload
        for key in ("requests", "batch", "documents", "files", "items", "archives"):
            if key in payload:
                return payload[key]
        return payload

    def _json_result(result):
        return jsonify(json.loads(json.dumps(result, default=str)))

    def _handle(path=""):
        payload = _payload()
        exchange = _exchange(payload if isinstance(payload, dict) else None)
        requests = _requests_from_payload(payload)
        lowered = path.lower()
        if "cancel" in lowered:
            if isinstance(payload, dict):
                result = exchange.cancel(**payload)
            else:
                result = exchange.cancel(payload)
        elif "replay" in lowered or "rerun" in lowered:
            result = exchange.replay(requests)
        elif "classif" in lowered or "root" in lowered:
            if isinstance(requests, list):
                result = {
                    "classifications": [
                        str(exchange.classify(item)) for item in requests
                    ]
                }
            else:
                result = {"classification": str(exchange.classify(requests))}
        elif "balance" in lowered:
            result = (
                exchange.get_balance(requests)
                if requests is not None
                else exchange.get_balance()
            )
            if not isinstance(result, dict):
                result = {"balance": result}
        else:
            result = exchange.settle(requests)
        return _json_result(result)

    @app.get("/health")
    def health():
        return jsonify({"ok": True})

    @app.get("/balance")
    @app.get("/api/balance")
    def balance():
        return _handle("balance")

    @app.post("/settle")
    @app.post("/receive")
    @app.post("/approve")
    @app.post("/intake")
    @app.post("/api/settle")
    def settle_named():
        return _handle("settle")

    @app.post("/cancel")
    @app.post("/api/cancel")
    def cancel_named():
        return _handle("cancel")

    @app.post("/replay")
    @app.post("/api/replay")
    def replay_named():
        return _handle("replay")

    @app.post("/<path:path>")
    def catch_post(path):
        return _handle(path)

    @app.get("/<path:path>")
    def catch_get(path):
        return _handle(path)

    return app


class _MissingFlaskApp(object):
    test_client = None
    run = None
