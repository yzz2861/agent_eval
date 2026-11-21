# Vendor audit fixture

`shared/` is deliberately cross-responsible:

- `vendor-a` owns `shared/alpha/` and `shared/joint/`.
- `vendor-b` owns `shared/beta/` and `shared/joint/`.
- `unassigned/` is not owned by either vendor.

The findings used by the tests are synthetic baseline entries. The source files contain
only comments, so this fixture cannot accidentally contain a usable credential.
