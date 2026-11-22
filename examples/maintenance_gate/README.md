# Offline maintenance gate example

Run the end-to-end demonstration of signed pause/resume slips, half sets,
rollback rejection, delegation overlap and cached target re-evaluation:

```
.venv/bin/python examples/maintenance_gate/demo_gate.py
```

See `tuf/contrib/maintenance_gate/README.md` for the design and the meaning of
the `trusted` / `staged` / `rejected` ingest states and the
`proceed` / `paused` / `pending` admission verdicts.
