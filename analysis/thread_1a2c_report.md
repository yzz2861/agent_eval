# Thread 0x1A2C reconciliation report

- dump file: `samples/thread_reuse_sample.dmp`
- dump timestamp: 2026-11-22 14:58:00 UTC

## Evidence (as recorded, no reconciliation applied)

- ThreadListStream: SuspendCount=1 PriorityClass=0x20 Priority=8 Teb=0x7FFDE000
- ThreadExListStream: SuspendCount=1 PriorityClass=0x20 Priority=9 Teb=0x7FFDE000
- ThreadInfoListStream record 1: DumpFlags=EXITED_THREAD (raw 0x4) DumpError=0x0 ExitStatus=0x0 Create=2026-11-22 14:00:00 UTC Exit=2026-11-22 14:37:00 UTC StartAddress=0x7FF610000000
- ThreadInfoListStream record 2: DumpFlags=(none) (raw 0x0) DumpError=0x0 ExitStatus=0x103 Create=2026-11-22 14:41:00 UTC Exit=- StartAddress=0x7FF610000000

## Conflicts and how the scene can still be explained

- Priority mismatch: ThreadList says 8, ThreadExList says 9. Both streams are written during the same dump but enumerate through different paths; a thread whose dynamic priority was being boosted/decayed while the dump was taken legitimately lands different values in the two streams. Neither value is discarded: treat the pair (8, 9) as the plausible range, and do not build conclusions on any single one.
- Same thread id appears 2 times in ThreadInfoList. The record(s) flagged EXITED_THREAD exited at 2026-11-22 14:37:00 UTC, BEFORE the current record was created at 2026-11-22 14:41:00 UTC. This is consistent with the OS recycling the thread id: the exited record describes a previous incarnation, not the thread that was dumped. Keep it as a historical clue only.
- The id is enumerated as live in ThreadListStream while a ThreadInfo record marks it EXITED_THREAD. Both can be true at once only if the id was reused; the create/exit timestamps above are the deciding evidence.

## Trust assessment

- [current] SuspendCount=1 is confirmed by BOTH enumerations: the thread was suspended at dump time. This directly supports the "never woke up" symptom.
- [unreliable] Priority: sources disagree (8 vs 9); archive both, trust neither on its own.
- [current] ThreadInfo: created 2026-11-22 14:41:00 UTC, still active (ExitStatus=0x103), flags (none).
- [stale-clue] ThreadInfo: created 2026-11-22 14:00:00 UTC, exited 2026-11-22 14:37:00 UTC. Previous incarnation of id 0x1A2C; explains old log lines but says nothing about the dumped thread.
