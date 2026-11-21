# Matcher impact assessment

- Samples: `3` (sha256=`eef1e275f58f76c1145d316a677cc342083aab5ecb3d0ee32bd7b295c0f90008`)
- Routing before: `examples/impact/before_routes.json` sha256=`05b89104d1bc0d816fdf21b279890c37aec3bfae57d4ab5d232c8b78614789c2`
- Routing after: `examples/impact/after_routes.json` sha256=`6b06765295894e9641bd97f75b3296f9b34a5db2dd4b71fa732cdae1633da95e`

## Summary

- `unchanged`: 1
- `new_format`: 1
- `new_unrouted`: 0
- `downgrade`: 1
- `upgrade`: 0
- `lateral_reroute`: 0
- `coverage_lost`: 0
- `isolation_changed`: 2
- `precedence_changed`: 2
- `error_affected_samples`: 3
- `unrouted_new_formats`: 0

## Changed isolation decisions

| Sample | Decision | Before | After |
| --- | --- | --- | --- |
| `sample.jpg` | `downgrade` | jpg (image/jpeg) / image-strong cap=10 | legacy-jpg (image/x-legacy-jpeg) / legacy-weak cap=2 |
| `new.foo` | `new_format` | <no match> / <no route> | foo (application/x-foo) / new-medium cap=6 |

## New legitimate formats

| Sample | Format | Queue |
| --- | --- | --- |
| `new.foo` | foo (application/x-foo) | new-medium cap=6 |

## Legacy files moved to a weaker queue

| Sample | Before | After |
| --- | --- | --- |
| `sample.jpg` | jpg (image/jpeg) / image-strong cap=10 | legacy-jpg (image/x-legacy-jpeg) / legacy-weak cap=2 |

## Matcher errors

Affected samples: `sample.jpg`, `sample.png`, `new.foo`

| Sample | Side | Matcher | Rank | Error |
| --- | --- | --- | --- | --- |
| `sample.jpg` | `after` | `examples.impact.thirdparty.BrokenType` | 1 | `RuntimeError: third-party matcher exploded` |
| `sample.png` | `after` | `examples.impact.thirdparty.BrokenType` | 1 | `RuntimeError: third-party matcher exploded` |
| `new.foo` | `after` | `examples.impact.thirdparty.BrokenType` | 1 | `RuntimeError: third-party matcher exploded` |

Routing configs: before `examples/impact/before_routes.json` (`05b89104d1bc0d816fdf21b279890c37aec3bfae57d4ab5d232c8b78614789c2`), after `examples/impact/after_routes.json` (`6b06765295894e9641bd97f75b3296f9b34a5db2dd4b71fa732cdae1633da95e`).
