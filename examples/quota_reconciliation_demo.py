"""Offline exception-quota reconciliation demo.

The scenario mirrors a count-based Sigma rule whose ticket window allows two
known/benign operations to be ignored. Events arrive from several collectors,
so the same real-world event can be forwarded twice. Later information can
also confirm that two records were not the same event.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sigma.quota import (
    CallerHints,
    Correction,
    QuotaReconciler,
    TumblingWindow,
    observations_from_dicts,
    render_report,
)

UTC = timezone.utc
T0 = datetime(2026, 11, 23, 10, 0, tzinfo=UTC)


def at(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


def main() -> str:
    hints = CallerHints(
        identity_field="event_id",
        group_field="host",
        exempt_scope="known_operation",
        timestamp_field="event_time",
    )
    records = [
        {"event_id": "evt-1", "host": "web-01", "known_operation": True,
         "event_time": at(30).isoformat(), "ingested_at": at(30).isoformat()},
        {"event_id": "evt-1", "host": "web-01", "known_operation": True,
         "event_time": at(30).isoformat(), "ingested_at": at(35).isoformat()},
        {"event_id": "evt-2", "host": "web-01", "known_operation": True,
         "event_time": at(90).isoformat(), "ingested_at": at(90).isoformat()},
        {"event_id": "evt-3", "host": "web-01", "known_operation": True,
         "event_time": at(150).isoformat(), "ingested_at": at(150).isoformat()},
        {"event_id": "evt-4", "host": "web-01", "known_operation": False,
         "event_time": at(210).isoformat(), "ingested_at": at(210).isoformat()},
        {"event_id": "evt-5", "host": "web-01", "known_operation": True,
         "event_time": at(45).isoformat(), "ingested_at": at(730).isoformat()},
        {"event_id": "evt-late", "host": "web-01", "known_operation": True,
         "event_time": at(50).isoformat(), "ingested_at": at(760).isoformat()},
        {"event_id": "evt-6", "host": "web-01", "known_operation": True,
         "event_time": at(660).isoformat(), "ingested_at": at(660).isoformat()},
    ]
    observations = observations_from_dicts(records, hints, ingest_field="ingested_at")
    reconciler = QuotaReconciler(
        TumblingWindow(timedelta(minutes=10)),
        quota=2,
        allowed_lateness=timedelta(minutes=2),
    )
    for observation in observations:
        reconciler.observe(observation)
    reconciler.correct(
        Correction(
            original_event_id="evt-3",
            new_event_id="evt-3-distinct",
            group_key="web-01",
            event_time=at(150),
            received_time=at(900),
            new_exempt=False,
            reason="analyst confirmed the records describe different processes",
        )
    )
    result = reconciler.finish()
    return render_report(result)


if __name__ == "__main__":
    print(main())
