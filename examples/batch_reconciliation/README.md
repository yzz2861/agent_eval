# Batch reconciliation example

Three small documents are reconciled by `examples/batch_reconciliation.py`:

* `batch_list.json` - independent delivery-batch list.
* `review_scope.json` - the middle document, declaring which sub-packages one shared quality record covers.
* `physical_witness.json` - the concrete sub-packages observed during review.

Removing the middle document makes the effective coverage of both delivery batches fall. The example prints that delta and names both batches.
