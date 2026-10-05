# Adaptive Admission Control

Puma's thread pool has a fixed size, but the concurrency an application can
actually sustain shifts with downstream latency (databases, APIs, etc.).
Adaptive admission control closes that gap: it limits how many requests may
execute inside the application concurrently and adjusts that limit from
windowed statistics of queue wait and completion latency. The thread pool
itself is never rebuilt — pool threads simply wait at the admission gate when
the limit is reached.

It is disabled by default. Enable it in your config file:

```ruby
adaptive_admission min: 1, max: 16, target_latency: 0.5, window: 5.0
```

`max` defaults to `max_threads` when omitted.

## How the limit is adjusted

Completed requests are grouped into windows of `window` seconds (measured on
a monotonic clock). When a window closes, the controller computes:

```
observed  = mean(queue_wait + service_time) of *successful* completions
raw       = limit * target_latency / observed
```

and rate-limits the move:

```
increase  = min(raw, limit + 1)     # additive, slow growth
decrease  = max(raw, limit * 0.8)   # multiplicative, quick cut
```

The candidate is only applied when the relative change is at least 10%
(hysteresis, to damp oscillation), and the result is clamped to `[min, max]`.

## Edge cases

- **Idle**: a window with too few completions (including a completely empty
  window) is discarded and never changes the limit.
- **Failures**: failed requests are excluded from the latency mean. If the
  failure ratio of a window reaches 50%, the limit is cut to
  `max(min, floor(limit * 0.8))` regardless of latency, because errors under
  load are themselves an overload signal.
- **Decreasing**: the limit is only a counter. In-flight requests always run
  to natural completion; new admissions wait until in-flight drops below the
  new limit. Nothing is killed and no pool thread is recreated.
- **Clock**: all timing uses a monotonic clock, so wall-clock jumps do not
  corrupt the statistics.

When enabled, the server's stats include `admission_limit`, the current
concurrency limit.
