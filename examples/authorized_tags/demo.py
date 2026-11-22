"""Interleaved-load demo for instance-isolated authorized safe loading.

Run: python examples/authorized_tags/demo.py

Two YAML configs are read by the same process with different tag policies.
The internal team authority may register !team/* tags; the third-party
upload authority only accepts !vendor/* tags. Logs show which loader
instance accepts or rejects the custom tag, and revocation is decided on
the authority's current scope rather than on prior audit records.
"""

import logging

from yaml.constructor import ConstructorError
from yaml.authorized import (
    TagAuthority,
    authorized_safe_load,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)


def team_marker(loader, node):
    return {"team_marker": loader.construct_scalar(node)}


def vendor_widget(loader, node):
    return {"vendor_widget": loader.construct_scalar(node)}


team = TagAuthority("internal-team")
vendor = TagAuthority("third-party-uploads")
team.grant("!team/internal", team_marker)
vendor.grant("!vendor/widget", vendor_widget)

internal_doc = "name: service-config\nmarker: !team/internal 42\n"
upload_doc = "name: partner-upload\nmarker: !vendor/widget \"ok\"\n"


def attempt(label, stream, authority):
    print(f"--- {label} via authority {authority.name!r}")
    try:
        print("loaded:", authorized_safe_load(stream, authority))
    except ConstructorError as error:
        print("rejected:", str(error).splitlines()[0])


attempt("internal config", internal_doc, team)
attempt("internal config", internal_doc, vendor)
attempt("partner upload", upload_doc, vendor)
attempt("partner upload", upload_doc, team)

print("--- revoking !team/internal, then re-reading the internal config")
team.revoke("!team/internal")
attempt("internal config", internal_doc, team)

print("--- audit review for the revoked tag")
for event in team.review("!team/internal"):
    print(event)
