#!/usr/bin/env python3
"""Build fictional fork/rename materials and disclosure receipts.

Run from the repository root::

    .venv/bin/python examples/disclosure_receipt_demo.py

The script creates text artifacts, signed in-toto links, runs the existing
in-toto verifier for the authorized chains, and writes internal/public
disclosure receipts under ``disclosure-demo-output/``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from securesystemslib.signer import CryptoSigner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from in_toto.disclosure import build_disclosure_receipt  # noqa: E402
from in_toto.models.layout import Layout  # noqa: E402
from in_toto.models.link import FILENAME_FORMAT, Link  # noqa: E402
from in_toto.models.metadata import Metablock  # noqa: E402
from in_toto.verifylib import in_toto_verify  # noqa: E402

SHARED_STORY = "A fictional story about two tides and one lighthouse.\n"
PARTNER_BRIEF = "A shortened partner brief with a different digest.\n"
HIDDEN_DOSSIER = "An unauthorized branch dossier that must stay internal.\n"
LIGHTHOUSE_NOTES = "Fictional notes about a reusable harbor light.\n"
READING_COPY = "A formatted reading copy with a new product digest.\n"


def digest(text: str) -> dict[str, str]:
    """Return a sha256 hash dictionary for fictional text."""
    return {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def write_text_artifact(root: Path, relative: str, text: str) -> None:
    """Write one local fictional text artifact."""
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def public_key(signer: CryptoSigner) -> dict[str, Any]:
    """Return a public key dictionary including its keyid."""
    key = signer.public_key
    data = key.to_dict()
    data["keyid"] = key.keyid
    return data


def signed_link_file(
    *,
    directory: Path,
    name: str,
    materials: dict[str, dict[str, str]],
    products: dict[str, dict[str, str]],
    command: list[str],
    signer: CryptoSigner,
    key_id: str,
) -> Path:
    """Create, sign, verify, and persist one Link."""
    link = Link(
        name=name,
        materials=materials,
        products=products,
        command=command,
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(signer)
    metadata.verify_signature(public_key(signer))
    filename = FILENAME_FORMAT.format(step_name=name, keyid=key_id)
    path = directory / filename
    metadata.dump(str(path))
    return path


def build_materials(output: Path) -> dict[str, dict[str, str]]:
    """Write fork and rename artifact trees."""
    artifacts = output / "artifacts"
    fork_files = {
        "fork/story-seed.txt": SHARED_STORY,
        "fork/authorized-story.txt": SHARED_STORY,
        "fork/secret-story.txt": SHARED_STORY,
        "fork/partner-brief.txt": PARTNER_BRIEF,
        "fork/hidden-dossier.txt": HIDDEN_DOSSIER,
        "rename/draft-notes.txt": LIGHTHOUSE_NOTES,
        "rename/polished-notes.txt": LIGHTHOUSE_NOTES,
        "rename/reading-copy.txt": READING_COPY,
    }
    for relative, text in fork_files.items():
        write_text_artifact(artifacts, relative, text)

    return {
        "shared": digest(SHARED_STORY),
        "partner": digest(PARTNER_BRIEF),
        "hidden": digest(HIDDEN_DOSSIER),
        "notes": digest(LIGHTHOUSE_NOTES),
        "reading": digest(READING_COPY),
    }


def build_signed_links(
    output: Path, hashes: dict[str, dict[str, str]]
) -> tuple[
    dict[str, Path], CryptoSigner, dict[str, Any], dict[str, Any], str
]:
    """Build authorized and unauthorized signed links."""
    link_dir = output / "links"
    link_dir.mkdir(parents=True, exist_ok=True)
    signer = CryptoSigner.generate_ed25519()
    rogue_signer = CryptoSigner.generate_ed25519()
    key = public_key(signer)
    rogue_key = public_key(rogue_signer)
    key_id = key["keyid"]
    rogue_key_id = rogue_key["keyid"]

    key_dir = output / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / "authorized-public.json").write_text(
        json.dumps(key, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (key_dir / "unauthorized-public.json").write_text(
        json.dumps(rogue_key, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    shared = hashes["shared"]
    partner = hashes["partner"]
    hidden = hashes["hidden"]
    notes = hashes["notes"]
    reading = hashes["reading"]

    paths: dict[str, Path] = {}
    authorized_specs = [
        (
            "fork-origin",
            {},
            {"fork/story-seed.txt": shared},
            ["write", "story-seed"],
        ),
        (
            "fork-copy",
            {"fork/story-seed.txt": shared},
            {"fork/authorized-story.txt": shared},
            ["cp", "story-seed", "authorized-story"],
        ),
        (
            "fork-pack",
            {"fork/authorized-story.txt": shared},
            {"fork/partner-brief.txt": partner},
            ["pack", "partner-brief"],
        ),
        (
            "rename-author",
            {},
            {"rename/draft-notes.txt": notes},
            ["write", "draft-notes"],
        ),
        (
            "rename-step",
            {"rename/draft-notes.txt": notes},
            {"rename/polished-notes.txt": notes},
            ["mv", "draft-notes.txt", "polished-notes.txt"],
        ),
        (
            "rename-pack",
            {"rename/polished-notes.txt": notes},
            {"rename/reading-copy.txt": reading},
            ["pack", "reading-copy"],
        ),
    ]
    for name, materials, products, command in authorized_specs:
        paths[name] = signed_link_file(
            directory=link_dir,
            name=name,
            materials=materials,
            products=products,
            command=command,
            signer=signer,
            key_id=key_id,
        )

    unauthorized_specs = [
        (
            "fork-secret-copy",
            {"fork/story-seed.txt": shared},
            {"fork/secret-story.txt": shared},
            ["cp", "story-seed", "secret-story"],
        ),
        (
            "fork-hidden-pack",
            {"fork/secret-story.txt": shared},
            {"fork/hidden-dossier.txt": hidden},
            ["pack", "hidden-dossier"],
        ),
    ]
    for name, materials, products, command in unauthorized_specs:
        paths[name] = signed_link_file(
            directory=link_dir,
            name=name,
            materials=materials,
            products=products,
            command=command,
            signer=rogue_signer,
            key_id=rogue_key_id,
        )

    return paths, signer, key, rogue_key, key_id


def create_rule(pattern: str) -> list[str]:
    """Return a terminal CREATE rule."""
    return ["CREATE", pattern]


def match_rule(pattern: str, source_step: str) -> list[str]:
    """Return a MATCH rule against a prior step product."""
    return [
        "MATCH",
        pattern,
        "WITH",
        "PRODUCTS",
        "FROM",
        source_step,
    ]


def verify_authorized_layout(
    *,
    output: Path,
    signer: CryptoSigner,
    public_key_data: dict[str, Any],
    key_id: str,
) -> None:
    """Run the upstream in-toto verifier on both authorized chains."""
    disallow = ["DISALLOW", "*"]
    steps = [
        {
            "name": "fork-origin",
            "pubkeys": [key_id],
            "expected_materials": [],
            "expected_products": [
                create_rule("fork/story-seed.txt"),
                disallow,
            ],
        },
        {
            "name": "fork-copy",
            "pubkeys": [key_id],
            "expected_materials": [
                match_rule("fork/story-seed.txt", "fork-origin"),
                disallow,
            ],
            "expected_products": [
                create_rule("fork/authorized-story.txt"),
                disallow,
            ],
        },
        {
            "name": "fork-pack",
            "pubkeys": [key_id],
            "expected_materials": [
                match_rule("fork/authorized-story.txt", "fork-copy"),
                disallow,
            ],
            "expected_products": [
                create_rule("fork/partner-brief.txt"),
                disallow,
            ],
        },
        {
            "name": "rename-author",
            "pubkeys": [key_id],
            "expected_materials": [],
            "expected_products": [
                create_rule("rename/draft-notes.txt"),
                disallow,
            ],
        },
        {
            "name": "rename-step",
            "pubkeys": [key_id],
            "expected_materials": [
                match_rule("rename/draft-notes.txt", "rename-author"),
                disallow,
            ],
            "expected_products": [
                create_rule("rename/polished-notes.txt"),
                disallow,
            ],
        },
        {
            "name": "rename-pack",
            "pubkeys": [key_id],
            "expected_materials": [
                match_rule("rename/polished-notes.txt", "rename-step"),
                disallow,
            ],
            "expected_products": [
                create_rule("rename/reading-copy.txt"),
                disallow,
            ],
        },
    ]

    layout = Layout.read(
        {
            "_type": "layout",
            "keys": {key_id: public_key_data},
            "steps": steps,
            "inspect": [],
        }
    )
    metadata = Metablock(signed=layout)
    metadata.create_signature(signer)
    metadata.dump(str(output / "root.layout"))

    in_toto_verify(
        metadata,
        {key_id: public_key_data},
        link_dir_path=str(output / "links"),
        persist_inspection_links=False,
    )


def verified_step(
    *,
    name: str,
    paths: dict[str, Path],
    key_id: str,
    disclosure: dict[str, Any] | None = None,
    authorized: bool = True,
    source_divergent: bool = False,
) -> dict[str, Any]:
    """Build one caller-verified step request entry."""
    step: dict[str, Any] = {
        "name": name,
        "link": str(paths[name]),
        "authorized": authorized,
        "key_id": key_id,
    }
    if disclosure is not None:
        step["disclosure"] = disclosure
    if source_divergent:
        step["source_divergent"] = True
    return step


def match_basis(
    *,
    prior_step: str,
    prior_path: str,
    current_step: str,
    current_path: str,
    rule: list[Any],
) -> dict[str, Any]:
    """Build a forward product-to-material MATCH basis."""
    return {
        "source_step": prior_step,
        "source_kind": "products",
        "source_path": prior_path,
        "target_step": current_step,
        "target_kind": "materials",
        "target_path": current_path,
        "rule": rule,
    }


def transform_basis(
    *,
    step: str,
    material: str,
    product: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a material-to-product rule basis."""
    return {
        "step": step,
        "material": material,
        "product": product,
        "rule": rule,
    }


def fork_request(
    *,
    paths: dict[str, Path],
    hashes: dict[str, dict[str, str]],
    key_id: str,
    rogue_key_id: str,
) -> dict[str, Any]:
    """Create the fork request, including the unauthorized branch."""
    seed = "fork/story-seed.txt"
    authorized = "fork/authorized-story.txt"
    secret = "fork/secret-story.txt"
    partner = "fork/partner-brief.txt"
    hidden = "fork/hidden-dossier.txt"

    return {
        "approval": {
            "purpose": "partner-reading-copy",
            "hashes": hashes["partner"],
            "path": partner,
            "step": "fork-pack",
            "kind": "products",
            "public_label": "Two Tides brief",
        },
        "steps": [
            verified_step(
                name="fork-origin",
                paths=paths,
                key_id=key_id,
                disclosure={
                    "public_step": "source registration",
                    "approved_correlation": "two-tides-fiction",
                },
            ),
            verified_step(
                name="fork-copy",
                paths=paths,
                key_id=key_id,
                disclosure={
                    "public_step": "authorized copy",
                    "approved_correlation": "two-tides-fiction",
                },
            ),
            verified_step(
                name="fork-pack",
                paths=paths,
                key_id=key_id,
                disclosure={
                    "public_step": "partner packaging",
                    "approved_correlation": "two-tides-fiction",
                },
            ),
            verified_step(
                name="fork-secret-copy",
                paths=paths,
                key_id=rogue_key_id,
                authorized=False,
            ),
            verified_step(
                name="fork-hidden-pack",
                paths=paths,
                key_id=rogue_key_id,
                authorized=False,
            ),
        ],
        "rule_bases": [
            match_basis(
                prior_step="fork-origin",
                prior_path=seed,
                current_step="fork-copy",
                current_path=seed,
                rule=["MATCH", seed, "WITH", "PRODUCTS", "FROM", "fork-origin"],
            ),
            transform_basis(
                step="fork-copy",
                material=seed,
                product=authorized,
                rule={"rule_type": "checked-copy-map", "op": "cp"},
            ),
            match_basis(
                prior_step="fork-copy",
                prior_path=authorized,
                current_step="fork-pack",
                current_path=authorized,
                rule=[
                    "MATCH",
                    authorized,
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "fork-copy",
                ],
            ),
            transform_basis(
                step="fork-pack",
                material=authorized,
                product=partner,
                rule={"rule_type": "checked-pack-map"},
            ),
            match_basis(
                prior_step="fork-origin",
                prior_path=seed,
                current_step="fork-secret-copy",
                current_path=seed,
                rule=["MATCH", seed, "WITH", "PRODUCTS", "FROM", "fork-origin"],
            ),
            transform_basis(
                step="fork-secret-copy",
                material=seed,
                product=secret,
                rule={"rule_type": "unchecked-branch-copy"},
            ),
            match_basis(
                prior_step="fork-secret-copy",
                prior_path=secret,
                current_step="fork-hidden-pack",
                current_path=secret,
                rule=[
                    "MATCH",
                    secret,
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "fork-secret-copy",
                ],
            ),
            transform_basis(
                step="fork-hidden-pack",
                material=secret,
                product=hidden,
                rule={"rule_type": "hidden-pack-map"},
            ),
        ],
    }


def rename_request(
    *,
    paths: dict[str, Path],
    hashes: dict[str, dict[str, str]],
    key_id: str,
) -> dict[str, Any]:
    """Create the rename request."""
    draft = "rename/draft-notes.txt"
    polished = "rename/polished-notes.txt"
    reading = "rename/reading-copy.txt"

    correlation = "lighthouse-reading"
    return {
        "approval": {
            "purpose": "reading-club-distribution",
            "hashes": hashes["reading"],
            "path": reading,
            "step": "rename-pack",
            "kind": "products",
            "public_label": "Lighthouse Notes reading copy",
        },
        "steps": [
            verified_step(
                name="rename-author",
                paths=paths,
                key_id=key_id,
                disclosure={
                    "public_step": "drafting",
                    "approved_correlation": correlation,
                },
            ),
            verified_step(
                name="rename-step",
                paths=paths,
                key_id=key_id,
                disclosure={
                    "public_step": "rename and consistency check",
                    "approved_correlation": correlation,
                    "association": "same approved text after an approved rename",
                },
            ),
            verified_step(
                name="rename-pack",
                paths=paths,
                key_id=key_id,
                disclosure={
                    "public_step": "reading copy packaging",
                    "approved_correlation": correlation,
                },
            ),
        ],
        "rule_bases": [
            match_basis(
                prior_step="rename-author",
                prior_path=draft,
                current_step="rename-step",
                current_path=draft,
                rule=[
                    "MATCH",
                    draft,
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "rename-author",
                ],
            ),
            transform_basis(
                step="rename-step",
                material=draft,
                product=polished,
                rule={
                    "rule_type": "approved-rename",
                    "command": ["mv", draft, polished],
                },
            ),
            match_basis(
                prior_step="rename-step",
                prior_path=polished,
                current_step="rename-pack",
                current_path=polished,
                rule=[
                    "MATCH",
                    polished,
                    "WITH",
                    "PRODUCTS",
                    "FROM",
                    "rename-step",
                ],
            ),
            transform_basis(
                step="rename-pack",
                material=polished,
                product=reading,
                rule={"rule_type": "checked-pack-map"},
            ),
        ],
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    """Write one request or receipt JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def build_and_store(
    *,
    name: str,
    output: Path,
    request: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build receipts and persist request plus internal/public copies."""
    write_json(output / "requests" / f"{name}.json", request)
    bundle = build_disclosure_receipt(
        approval=request["approval"],
        steps=request["steps"],
        rule_bases=request["rule_bases"],
    )
    directory = output / "receipts" / name
    write_json(directory / "internal.json", bundle.internal)
    write_json(directory / "public.json", bundle.public)
    return bundle.internal, bundle.public


def assert_demo_properties(
    *,
    fork_public: dict[str, Any],
    purpose_public: dict[str, Any],
    rename_public: dict[str, Any],
    unauthorized_gap: dict[str, Any],
    divergence_gap: dict[str, Any],
    hashes: dict[str, dict[str, str]],
    rogue_key_id: str,
) -> None:
    """Check the confidentiality properties demonstrated by the script."""
    assert fork_public["provenance"]["status"] == "complete"
    assert [step["public_step"] for step in fork_public["steps"]] == [
        "source registration",
        "authorized copy",
        "partner packaging",
    ]

    fork_without_purpose = {
        key: value
        for key, value in fork_public.items()
        if key != "approved_use"
    }
    purpose_without_purpose = {
        key: value
        for key, value in purpose_public.items()
        if key != "approved_use"
    }
    assert fork_without_purpose == purpose_without_purpose
    assert purpose_public["approved_use"] == "classroom-reading-copy"

    fork_text = json.dumps(fork_public, sort_keys=True)
    forbidden = [
        "fork-secret-copy",
        "fork-hidden-pack",
        "secret-story.txt",
        "hidden-dossier.txt",
        rogue_key_id,
        hashes["shared"]["sha256"],
        hashes["partner"]["sha256"],
        hashes["hidden"]["sha256"],
    ]
    for marker in forbidden:
        assert marker not in fork_text

    assert rename_public["provenance"]["status"] == "complete"
    correlations = [
        step["approved_correlation"] for step in rename_public["steps"]
    ]
    assert correlations == ["lighthouse-reading"] * 3
    rename_text = json.dumps(rename_public, sort_keys=True)
    for marker in [
        "draft-notes.txt",
        "polished-notes.txt",
        hashes["notes"]["sha256"],
        hashes["reading"]["sha256"],
    ]:
        assert marker not in rename_text

    assert unauthorized_gap == divergence_gap
    assert unauthorized_gap["steps"] == []
    assert unauthorized_gap["provenance"]["status"] == "evidence_gap"


def main(argv: list[str] | None = None) -> int:
    """Generate local materials, verify chains, receipts, and assertions."""
    args = sys.argv[1:] if argv is None else argv
    output = Path(args[0]) if args else ROOT / "disclosure-demo-output"
    output.mkdir(parents=True, exist_ok=True)
    for child in ("artifacts", "links", "keys", "requests", "receipts"):
        shutil.rmtree(output / child, ignore_errors=True)
    (output / "root.layout").unlink(missing_ok=True)

    hashes = build_materials(output)
    paths, signer, key, rogue_key, key_id = build_signed_links(output, hashes)
    verify_authorized_layout(
        output=output,
        signer=signer,
        public_key_data=key,
        key_id=key_id,
    )

    rogue_key_id = rogue_key["keyid"]
    fork = fork_request(
        paths=paths,
        hashes=hashes,
        key_id=key_id,
        rogue_key_id=rogue_key_id,
    )
    rename = rename_request(paths=paths, hashes=hashes, key_id=key_id)

    _, fork_public = build_and_store(
        name="fork-partner", output=output, request=fork
    )

    purpose_only = copy.deepcopy(fork)
    purpose_only["approval"]["purpose"] = "classroom-reading-copy"
    _, purpose_public = build_and_store(
        name="fork-purpose-only",
        output=output,
        request=purpose_only,
    )

    _, rename_public = build_and_store(
        name="rename", output=output, request=rename
    )

    unauthorized = copy.deepcopy(fork)
    for step in unauthorized["steps"]:
        if step["name"] == "fork-pack":
            step["authorized"] = False
    _, unauthorized_gap = build_and_store(
        name="gap-unauthorized",
        output=output,
        request=unauthorized,
    )

    divergence = copy.deepcopy(fork)
    for step in divergence["steps"]:
        if step["name"] == "fork-pack":
            step["source_divergent"] = True
    _, divergence_gap = build_and_store(
        name="gap-source-divergence",
        output=output,
        request=divergence,
    )

    assert_demo_properties(
        fork_public=fork_public,
        purpose_public=purpose_public,
        rename_public=rename_public,
        unauthorized_gap=unauthorized_gap,
        divergence_gap=divergence_gap,
        hashes=hashes,
        rogue_key_id=rogue_key_id,
    )

    print(f"Disclosure demo materials and receipts: {output}")
    print("Existing in-toto signature and rule verification: passed")
    print("Fork, purpose-only, rename, and generic-gap checks: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
