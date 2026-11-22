# Privilege precheck example

Both migrations rename `public.orders`, grant `UPDATE` to `analyst`, and add
`DELETE` before rolling back to a savepoint.  Only the savepoint placement
differs:

- `migration_allowed.sql` creates the savepoint before `DELETE`, so the
  rollback removes `DELETE` from the committed state.
- `migration_manual_review.sql` creates the savepoint after `DELETE`, so the
  rollback has nothing to undo and `DELETE` is committed.

The reviewed allowlist in `state.json` permits only `UPDATE` on the stable
object identity `public.orders`.

Run either migration through the offline precheck:

```bash
python -m sqlparse.precheck \
  examples/privilege_precheck/migration_allowed.sql \
  --state examples/privilege_precheck/state.json
```

Expected decisions:

| migration | decision |
| --- | --- |
| `migration_allowed.sql` | `approved` |
| `migration_manual_review.sql` | `manual_review` |

In both reports the post-commit object is named `orders_archive`, while its
`object_id` remains `public.orders`.  That is how a privilege granted before
or after the rename is attributed to the same object.
