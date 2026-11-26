from _archive_compat import setup_module

setup_module(globals(), __name__)


def main(argv=None):
    import json
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("archive exchange compatibility CLI")
        return 0
    with open(args[0], "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    manifest = payload.get("manifest", {}) if isinstance(payload, dict) else {}
    requests = (
        payload.get("requests", payload) if isinstance(payload, dict) else payload
    )
    result = core_settle(manifest, requests)
    print(json.dumps({"balance": result["balance"], "ok": result["ok"]}, default=str))
    return 0 if result["ok"] else 1


from archive_exchange import settle_archives as core_settle  # noqa: E402
