# Offline maintenance-station update planner

This package answers one question for every device group before the network
is disconnected: **which is the last firmware install that can still be
verified and finished inside the maintenance window, and when does that
conclusion stop being valid?**

Everything runs offline against a fixed clock, so the same inputs always
produce the same verdict on any machine.

## Scenario

A vendor publishes self-contained TUF repositories (signed metadata plus the
firmware payload) into copyable release directories. Each device already
holds a trusted TUF root and reports its installed firmware and the metadata
version it trusted at inventory time.

Fixed timeline:

| Instant (UTC)            | Event |
|--------------------------|-------|
| 2026-11-20T00:00         | Inventory: devices report trust state |
| 2026-11-20T08:00         | release-a: firmware 1.4.0, metadata v2, 30d validity |
| 2026-11-21T00:00         | release-b: firmware 1.5.0, metadata v3, expires 10:00 |
| 2026-11-21T02:00         | release-c: firmware 1.6.0, metadata v4, 7d validity |
| 2026-11-21T06:00 - 12:00 | Maintenance window; installs take 2h of validity |

## Decision rules

1. Every release is verified locally through the full TUF client workflow
   (`TrustedMetadataSet` with a fixed reference time): signature thresholds,
   version/rollback checks and expiry checks, followed by a payload hash and
   length check.
2. Metadata and device versions advance independently. A release whose
   targets metadata version is newer than the version the group pinned at
   inventory time is rejected (`metadata-version-ahead`): an unverified
   update never replaces the trusted stock state.
3. A signed, unexpired release still needs enough remaining validity to
   finish the install. Its `install_deadline = verifiable_until -
   install_duration` must reach the window close; otherwise the bundle is
   signed but not installable in time.
4. Among the installable releases the newest published one wins. If none is
   installable, the group keeps its inventory firmware and the reason is
   reported.
5. Each conclusion carries `conclusion_expires_at`: the earlier of the
   selected release install deadline and the maintenance window close.

## Usage

Build the deterministic scenario and print the text report:

```
python -m maintenance.cli --build-scenario
```

Emit machine-readable JSON instead:

```
python -m maintenance.cli --build-scenario --json
```

Run the acceptance tests:

```
python -m unittest tests.test_maintenance_planner -v
```
