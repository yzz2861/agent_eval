# Regression fixture for B616/B617. All names below are fake markers.
import logging


def clean_case(logger):
    req = fake_api.read_request()
    safe_card = fake_sec.mask_card(req["fake_card_no"])
    logger.info("fake-event", extra={"fake_card_no": safe_card})


def overwrite_case(logger):
    req = fake_api.read_request()
    card = fake_sec.mask_card(req["fake_card_no"])
    card = req["fake_card_no"]
    logger.error("fake-event", extra={"fake_card_no": card})


def fallback_case(logger):
    req = fake_api.read_request()
    try:
        card = fake_sec.mask_card(req["fake_card_no"])
    except fake_exc.FakeError:
        card = req["fake_card_no"]
    logger.exception("fake-event", extra={"fake_card_no": card})


def alias_unpack_case(logger):
    req = fake_api.read_request()
    snapshot = req
    details = {"fake_note": "x"}
    details.update(snapshot)
    logger.info("fake-event", extra={"fake_outer": 1, **details})


def unverified_case(logger):
    req = fake_api.read_request()
    transformed = fake_vendor.normalize(req)
    logger.error("fake-event", extra={"fake_card_no": transformed})
