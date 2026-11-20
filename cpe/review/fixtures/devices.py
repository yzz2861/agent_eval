"""
Fictional self-test inventory for the offline CPE review layer.

Three devices are provided:

- ``gw-alpha-01`` and ``gw-bravo-02`` carry queryable component records
  (firmware, a distribution package and package components) plus explicit
  parent links, so containment can be proven.
- ``gw-charlie-03`` only carries a supplier declaration: the supplier name
  is known but no component record can be queried, so it stays in the
  manual-review bucket.

Every device also lists an enclosure CPE.  Enclosures share the supplier
product-naming layer (``acme:gx_*``) but are physical hardware records.
They are included deliberately to prove that name-layer similarity never
pulls an enclosure into the remediation scope.
"""

from ..model import Asset, AdvisoryEntry


VENDOR = "acme"

# Advisory CPEs (ranges use wildcards, as real advisories do).
ADV_FIRMWARE = "cpe:2.3:a:acme:gx_firmware:*:*:*:*:*:*:*:*"
ADV_DIST = "cpe:2.3:a:acme:secure_dist:*:*:*:*:*:*:*:*"
ADV_PACKET_ENGINE = "cpe:2.3:a:acme:packet_engine:*:*:*:*:*:*:*:*"
ADV_TLS_KIT = "cpe:2.3:a:acme:tls_kit:*:*:*:*:*:*:*:*"

# An alternative registered name for the same firmware binary.
# Inventory documents declare it as a same-identity alias of gx_firmware.
ALPHA_FIRMWARE_ALT = "cpe:2.3:a:acme:gx_firmware_ng:4.2.1:*:*:*:*:*:*:*"

def _cpe(part, product, version="*", vendor=VENDOR):
    return "cpe:2.3:{0}:{1}:{2}:{3}:*:*:*:*:*:*:*".format(
        part, vendor, product, version)


def build_advisories():
    """Advisory entries used by every self-test scenario."""
    return [
        AdvisoryEntry("ADV-2026-0001", ADV_FIRMWARE,
                      "GX firmware verification bypass"),
        AdvisoryEntry("ADV-2026-0002", ADV_DIST,
                      "SecureDist bundle privilege escalation"),
        # No dedicated advisory for packet_engine: the component is
        # inside the secure_dist bundle and is reached only by walking the
        # provable containment chain of ADV-2026-0002.
        AdvisoryEntry("ADV-2026-0004", ADV_TLS_KIT,
                      "TLSKit certificate validation flaw"),
    ]


def build_assets():
    """The three fictional devices, two queryable and one declaration only."""
    alpha_device = _cpe("h", "gx_200", "r2")
    alpha_firmware = _cpe("a", "gx_firmware", "4.2.1")
    alpha_dist = _cpe("a", "secure_dist", "1.8.0")
    alpha_engine = _cpe("a", "packet_engine", "3.1.4")
    alpha_tls = _cpe("a", "tls_kit", "2.0.7")
    alpha_enclosure = _cpe("h", "gx_200_enclosure", "1.0")

    bravo_device = _cpe("h", "gx_300", "r1")
    bravo_firmware = _cpe("a", "gx_firmware", "4.2.1")
    bravo_dist = _cpe("a", "secure_dist", "1.8.0")
    bravo_engine = _cpe("a", "packet_engine", "3.1.4")
    bravo_tls = _cpe("a", "tls_kit", "2.0.7")
    bravo_enclosure = _cpe("h", "gx_300_enclosure", "1.0")

    charlie_device = _cpe("h", "gx_400", "r1")
    # No queryable component CPEs: only the supplier name is known.
    charlie_claimed_tls = _cpe("a", "tls_kit", "2.0.7")
    charlie_enclosure = _cpe("h", "gx_400_enclosure", "1.0")

    alpha = Asset(
        asset_id="gw-alpha-01",
        hostname="alpha.example.net",
        device_cpe=alpha_device,
        component_cpes=[alpha_firmware, alpha_dist, alpha_engine, alpha_tls],
        enclosure_cpes=[alpha_enclosure],
        parent_links={
            alpha_device: [alpha_firmware],
            alpha_firmware: [alpha_dist],
            alpha_dist: [alpha_engine, alpha_tls],
        },
        identity_aliases=[
            [alpha_firmware, ALPHA_FIRMWARE_ALT],
        ])

    bravo = Asset(
        asset_id="gw-bravo-02",
        hostname="bravo.example.net",
        device_cpe=bravo_device,
        component_cpes=[bravo_firmware, bravo_dist, bravo_engine, bravo_tls],
        enclosure_cpes=[bravo_enclosure],
        parent_links={
            bravo_device: [bravo_firmware],
            bravo_firmware: [bravo_dist],
            bravo_dist: [bravo_engine, bravo_tls],
        })

    charlie = Asset(
        asset_id="gw-charlie-03",
        hostname="charlie.example.net",
        device_cpe=charlie_device,
        component_cpes=[],
        enclosure_cpes=[charlie_enclosure],
        supplier_claims={
            charlie_claimed_tls: "Acme Supply Chain Desk",
        })

    return [alpha, bravo, charlie]

def build_updated_assets():
    """
    Inventory update used for the proof-disappearance self-test.

    On gw-alpha-01 the TLSKit and PacketEngine records are removed and
    every child link of ``secure_dist`` is dropped, so the TLSKit identity
    proof and both PacketEngine containment proofs disappear.  gw-bravo-02
    keeps every record.  gw-charlie-03 loses even the supplier declaration.
    """
    assets = build_assets()
    alpha, bravo, charlie = assets

    tls_cpe = _cpe("a", "tls_kit", "2.0.7")
    engine_cpe = _cpe("a", "packet_engine", "3.1.4")
    alpha.component_cpes = [
        cpe for cpe in alpha.component_cpes
        if cpe not in (tls_cpe, engine_cpe)]
    dist_cpe = _cpe("a", "secure_dist", "1.8.0")
    alpha.parent_links[dist_cpe] = []

    charlie.supplier_claims = {}
    return [alpha, bravo, charlie]
