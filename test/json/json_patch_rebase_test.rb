# frozen_string_literal: true

require_relative 'test_helper'
require 'json/patch_rebase'

class JSONPatchRebaseTest < Test::Unit::TestCase
  def rebase(base, applied, patch)
    JSON::PatchRebase.rebase(base: base, applied: applied, patch: patch)
  end

  def apply(document, patch)
    JSON::PatchRebase.apply(document, patch)
  end

  def test_array_insert_shifts_following_indices
    result = rebase(
      { "list" => [1, 2, 3] },
      [{ "op" => "add", "path" => "/list/0", "value" => 0 }],
      [{ "op" => "replace", "path" => "/list/1", "value" => 9 }]
    )
    assert_predicate result, :ok?
    assert_equal [{ "op" => "replace", "path" => "/list/2", "value" => 9 }], result.patch
    assert_equal({ "list" => [0, 1, 9, 3] }, result.document)
  end

  def test_path_evolution_across_consecutive_array_operations
    # The first patch removes two elements and inserts one; a uniform
    # "+1 to every index" rule cannot express the resulting shift.
    applied = [
      { "op" => "remove", "path" => "/list/0" },
      { "op" => "remove", "path" => "/list/2" },
      { "op" => "add", "path" => "/list/1", "value" => "x" },
    ]
    result = rebase(
      { "list" => %w[a b c d e] },
      applied,
      [{ "op" => "replace", "path" => "/list/4", "value" => "E" }]
    )
    assert_predicate result, :ok?
    assert_equal "/list/3", result.patch[0]["path"]
    assert_equal({ "list" => %w[b x c E] }, result.document)
  end

  def test_second_patch_own_array_operations_stay_in_sync
    # The second patch removes an element itself; later operations of the
    # same patch must be transformed against the remaining effects only.
    result = rebase(
      { "list" => %w[a b c] },
      [{ "op" => "remove", "path" => "/list/0" }],
      [
        { "op" => "remove", "path" => "/list/0" },
        { "op" => "replace", "path" => "/list/1", "value" => "Z" },
      ]
    )
    assert_predicate result, :ok?
    # The duplicated remove is dropped, the replace keeps targeting "c".
    assert_equal [{ "op" => "replace", "path" => "/list/1", "value" => "Z" }], result.patch
    assert_equal [0], result.notes.map(&:index)
    assert_equal({ "list" => %w[b Z] }, result.document)
  end

  def test_both_patches_insert_at_the_same_index
    result = rebase(
      { "list" => %w[a] },
      [{ "op" => "add", "path" => "/list/0", "value" => "x" }],
      [{ "op" => "add", "path" => "/list/0", "value" => "y" }]
    )
    assert_predicate result, :ok?
    assert_equal "/list/1", result.patch[0]["path"]
    assert_equal({ "list" => %w[x y a] }, result.document)
  end

  def test_remove_and_insert_at_same_index_keep_anchor
    result = rebase(
      { "list" => %w[a b c] },
      [{ "op" => "add", "path" => "/list/1", "value" => "x" }],
      [
        { "op" => "remove", "path" => "/list/1" },
        { "op" => "replace", "path" => "/list/1", "value" => "Z" },
      ]
    )
    assert_predicate result, :ok?
    assert_equal "/list/2", result.patch[0]["path"]
    assert_equal "/list/2", result.patch[1]["path"]
    assert_equal({ "list" => %w[a x Z] }, result.document)
  end

  def test_move_retargets_paths_into_moved_subtree
    result = rebase(
      { "a" => { "x" => 1 }, "b" => 2 },
      [{ "op" => "move", "from" => "/a", "path" => "/c" }],
      [{ "op" => "replace", "path" => "/a/x", "value" => 9 }]
    )
    assert_predicate result, :ok?
    assert_equal "/c/x", result.patch[0]["path"]
    assert_equal({ "b" => 2, "c" => { "x" => 9 } }, result.document)
  end

  def test_move_inside_same_array_shifts_siblings
    base = { "list" => %w[a b c d] }
    applied = [{ "op" => "move", "from" => "/list/0", "path" => "/list/2" }]

    result = rebase(base, applied, [{ "op" => "replace", "path" => "/list/0", "value" => "A" }])
    assert_equal "/list/2", result.patch[0]["path"]
    assert_equal({ "list" => %w[b c A d] }, result.document)

    result = rebase(base, applied, [{ "op" => "replace", "path" => "/list/1", "value" => "B" }])
    assert_equal "/list/0", result.patch[0]["path"]
    assert_equal({ "list" => %w[B c a d] }, result.document)

    result = rebase(base, applied, [{ "op" => "replace", "path" => "/list/3", "value" => "D" }])
    assert_equal "/list/3", result.patch[0]["path"]
    assert_equal({ "list" => %w[b c a D] }, result.document)
  end

  def test_conflict_when_both_patches_change_the_same_value
    result = rebase(
      { "v" => 1 },
      [{ "op" => "replace", "path" => "/v", "value" => 2 }],
      [{ "op" => "replace", "path" => "/v", "value" => 3 }]
    )
    assert_predicate result, :conflict?
    assert_nil result.patch
    assert_equal [0], result.conflicts.map(&:index)
    assert_equal :target_changed, result.conflicts[0].reason
  end

  def test_identical_replace_is_deduped_not_a_conflict
    result = rebase(
      { "v" => 1 },
      [{ "op" => "replace", "path" => "/v", "value" => 2 }],
      [{ "op" => "replace", "path" => "/v", "value" => 2 }]
    )
    assert_predicate result, :ok?
    assert_equal [], result.patch
    assert_equal [0], result.notes.map(&:index)
    assert_equal({ "v" => 2 }, result.document)
  end

  def test_conflict_when_ancestor_removed
    result = rebase(
      { "a" => { "b" => 1 } },
      [{ "op" => "remove", "path" => "/a" }],
      [
        { "op" => "replace", "path" => "/a/b", "value" => 2 },
        { "op" => "remove", "path" => "/a/b" },
      ]
    )
    assert_predicate result, :conflict?
    assert_equal [0, 1], result.conflicts.map(&:index)
    assert_equal %i[ancestor_removed ancestor_removed], result.conflicts.map(&:reason)
  end

  def test_conflict_when_move_source_already_moved
    result = rebase(
      { "a" => 1, "b" => 2 },
      [{ "op" => "move", "from" => "/a", "path" => "/c" }],
      [{ "op" => "move", "from" => "/a", "path" => "/d" }]
    )
    assert_predicate result, :conflict?
    assert_equal :source_changed, result.conflicts[0].reason
    assert_equal 0, result.conflicts[0].index
  end

  def test_move_source_inside_moved_subtree_is_retargeted
    result = rebase(
      { "a" => { "x" => 1 }, "b" => 2 },
      [{ "op" => "move", "from" => "/a", "path" => "/c" }],
      [{ "op" => "move", "from" => "/a/x", "path" => "/d" }]
    )
    assert_predicate result, :ok?
    assert_equal "/c/x", result.patch[0]["from"]
    assert_equal({ "b" => 2, "c" => {}, "d" => 1 }, result.document)
  end

  def test_conflict_when_tested_value_changed
    result = rebase(
      { "v" => 1 },
      [{ "op" => "replace", "path" => "/v", "value" => 2 }],
      [{ "op" => "test", "path" => "/v", "value" => 1 }]
    )
    assert_predicate result, :conflict?
    assert_equal :test_failed, result.conflicts[0].reason
  end

  def test_test_operation_survives_unrelated_changes
    result = rebase(
      { "v" => 1, "list" => [1, 2] },
      [{ "op" => "add", "path" => "/list/0", "value" => 0 }],
      [{ "op" => "test", "path" => "/list/1", "value" => 2 }]
    )
    assert_predicate result, :ok?
    assert_equal "/list/2", result.patch[0]["path"]
  end

  def test_copy_source_removed_is_a_conflict
    result = rebase(
      { "a" => 1 },
      [{ "op" => "remove", "path" => "/a" }],
      [{ "op" => "copy", "from" => "/a", "path" => "/b" }]
    )
    assert_predicate result, :conflict?
    assert_equal :source_changed, result.conflicts[0].reason
  end

  def test_copy_target_shifts_with_array_insert
    result = rebase(
      { "list" => [1, 2], "v" => 9 },
      [{ "op" => "add", "path" => "/list/0", "value" => 0 }],
      [{ "op" => "copy", "from" => "/v", "path" => "/list/1" }]
    )
    assert_predicate result, :ok?
    assert_equal "/list/2", result.patch[0]["path"]
    assert_equal({ "list" => [0, 1, 9, 2], "v" => 9 }, result.document)
  end

  def test_conflicts_keep_original_operation_numbers
    result = rebase(
      { "a" => 1, "b" => 2, "c" => 3 },
      [
        { "op" => "replace", "path" => "/a", "value" => 10 },
        { "op" => "remove", "path" => "/c" },
      ],
      [
        { "op" => "replace", "path" => "/b", "value" => 20 },
        { "op" => "replace", "path" => "/a", "value" => 30 },
        { "op" => "replace", "path" => "/c", "value" => 40 },
      ]
    )
    assert_predicate result, :conflict?
    assert_equal [1, 2], result.conflicts.map(&:index)
    assert_equal %i[target_changed target_removed], result.conflicts.map(&:reason)
    assert_equal "/a", result.conflicts[0].op["path"]
  end

  def test_origins_map_rebased_operations_to_original_numbers
    result = rebase(
      { "list" => [1, 2], "v" => 1 },
      [{ "op" => "replace", "path" => "/v", "value" => 1 }],
      [
        { "op" => "replace", "path" => "/v", "value" => 1 },
        { "op" => "add", "path" => "/list/-", "value" => 3 },
      ]
    )
    assert_predicate result, :ok?
    # First operation is redundant (same value), second one is emitted.
    assert_equal [1], result.origins
    assert_equal [{ "op" => "add", "path" => "/list/-", "value" => 3 }], result.patch
  end

  def test_add_of_same_object_member_with_different_value_conflicts
    result = rebase(
      {},
      [{ "op" => "add", "path" => "/k", "value" => 1 }],
      [{ "op" => "add", "path" => "/k", "value" => 2 }]
    )
    assert_predicate result, :conflict?
    assert_equal :target_changed, result.conflicts[0].reason
  end

  def test_append_dash_is_not_shifted
    result = rebase(
      { "list" => [1] },
      [{ "op" => "remove", "path" => "/list/0" }],
      [{ "op" => "add", "path" => "/list/-", "value" => 2 }]
    )
    assert_predicate result, :ok?
    assert_equal "/list/-", result.patch[0]["path"]
    assert_equal({ "list" => [2] }, result.document)
  end

  def test_replace_of_root_makes_everything_conflict
    result = rebase(
      { "a" => 1 },
      [{ "op" => "replace", "path" => "", "value" => { "b" => 2 } }],
      [{ "op" => "replace", "path" => "/a", "value" => 3 }]
    )
    assert_predicate result, :conflict?
    assert_equal :ancestor_changed, result.conflicts[0].reason
  end

  def test_invalid_applied_patch_raises
    assert_raise(JSON::PatchRebase::InvalidPatch) do
      rebase({ "a" => 1 }, [{ "op" => "remove", "path" => "/missing" }], [])
    end
  end

  def test_invalid_second_patch_raises
    assert_raise(JSON::PatchRebase::InvalidPatch) do
      rebase({ "a" => 1 }, [], [{ "op" => "remove", "path" => "/missing" }])
    end
  end

  def test_apply_validates_and_returns_new_document
    document = { "list" => [1, 2] }
    result = apply(document, [{ "op" => "add", "path" => "/list/-", "value" => 3 }])
    assert_equal({ "list" => [1, 2, 3] }, result)
    assert_equal({ "list" => [1, 2] }, document)
    assert_raise(JSON::PatchRebase::InvalidPatch) do
      apply(document, [{ "op" => "test", "path" => "/list/0", "value" => 2 }])
    end
  end

  def test_move_backwards_inside_same_array
    result = rebase(
      { "list" => %w[a b c d] },
      [{ "op" => "move", "from" => "/list/3", "path" => "/list/1" }],
      [
        { "op" => "replace", "path" => "/list/1", "value" => "B" },
        { "op" => "replace", "path" => "/list/3", "value" => "D" },
      ]
    )
    assert_predicate result, :ok?
    assert_equal "/list/2", result.patch[0]["path"]
    assert_equal "/list/1", result.patch[1]["path"]
    assert_equal({ "list" => %w[a D B c] }, result.document)
  end

  def test_second_patch_removes_the_moved_element
    result = rebase(
      { "list" => %w[a b c d] },
      [{ "op" => "move", "from" => "/list/0", "path" => "/list/2" }],
      [
        { "op" => "remove", "path" => "/list/0" },
        { "op" => "replace", "path" => "/list/0", "value" => "Z" },
      ]
    )
    assert_predicate result, :ok?
    assert_equal "/list/2", result.patch[0]["path"]
    assert_equal "/list/0", result.patch[1]["path"]
    assert_equal({ "list" => %w[Z c d] }, result.document)
  end

  def test_symbol_keys_are_accepted
    result = rebase(
      { "v" => 1 },
      [{ op: "replace", path: "/v", value: 2 }],
      [{ op: "replace", path: "/v", value: 3 }]
    )
    assert_predicate result, :conflict?
  end
end
