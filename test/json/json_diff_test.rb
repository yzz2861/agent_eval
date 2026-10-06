# frozen_string_literal: true

require_relative 'test_helper'

class JSONDiffTest < Test::Unit::TestCase
  def assert_round_trip(old_document, new_document, identity: nil)
    patch = JSON::Diff.generate(old_document, new_document, identity: identity)
    assert_equal new_document, JSON::Diff.apply(old_document, patch)
    patch
  end

  def test_identical_documents_produce_empty_patch
    document = { "a" => [1, 2, { "b" => "c" }], "d" => nil }
    assert_equal [], JSON::Diff.generate(document, document)
  end

  def test_scalar_replace
    assert_equal [{ "op" => "replace", "path" => "", "value" => 2 }],
      JSON::Diff.generate(1, 2)
    assert_equal [{ "op" => "replace", "path" => "/a", "value" => false }],
      JSON::Diff.generate({ "a" => true }, { "a" => false })
  end

  def test_integer_and_float_are_not_confused
    patch = JSON::Diff.generate({ "n" => 1 }, { "n" => 1.0 })
    assert_equal [{ "op" => "replace", "path" => "/n", "value" => 1.0 }], patch
  end

  def test_object_add_remove_replace
    patch = JSON::Diff.generate(
      { "keep" => 1, "drop" => 2, "change" => 3 },
      { "keep" => 1, "change" => 30, "new" => 4 }
    )
    assert_equal [
      { "op" => "remove", "path" => "/drop" },
      { "op" => "replace", "path" => "/change", "value" => 30 },
      { "op" => "add", "path" => "/new", "value" => 4 },
    ], patch
  end

  def test_pointer_escaping_in_keys
    old_document = { "a/b" => 1, "c~d" => 2, "tilde~1/slash" => 3 }
    new_document = { "a/b" => 10, "c~d" => 2, "tilde~1/slash" => 30 }
    patch = JSON::Diff.generate(old_document, new_document)
    assert_equal [
      { "op" => "replace", "path" => "/a~1b", "value" => 10 },
      { "op" => "replace", "path" => "/tilde~01~1slash", "value" => 30 },
    ], patch
    assert_equal new_document, JSON::Diff.apply(old_document, patch)
  end

  def test_array_element_change_is_not_a_wholesale_replace
    patch = JSON::Diff.generate([1, 2, 3], [1, 99, 3])
    assert_equal [{ "op" => "replace", "path" => "/1", "value" => 99 }], patch
  end

  def test_array_append_and_truncate_without_identity
    assert_equal [{ "op" => "add", "path" => "/-", "value" => 4 }],
      JSON::Diff.generate([1, 2, 3], [1, 2, 3, 4])
    assert_equal [
      { "op" => "remove", "path" => "/2" },
      { "op" => "remove", "path" => "/1" },
    ], JSON::Diff.generate([1, 2, 3], [1])
  end

  def test_positional_fallback_never_emits_move
    patch = JSON::Diff.generate([1, 2, 3], [3, 1, 2])
    assert_empty patch.select { |op| op["op"] == "move" }
    assert_equal [3, 1, 2], JSON::Diff.apply([1, 2, 3], patch)
  end

  def test_identity_detects_move
    old_rows = [{ "id" => 1 }, { "id" => 2 }, { "id" => 3 }]
    new_rows = [{ "id" => 3 }, { "id" => 1 }, { "id" => 2 }]
    identity = ->(row) { row["id"] }
    patch = assert_round_trip(old_rows, new_rows, identity: identity)
    assert_equal [{ "op" => "move", "from" => "/2", "path" => "/0" }], patch
  end

  def test_identity_move_add_remove_and_edit_combined
    old_rows = [
      { "id" => 1, "v" => "a" },
      { "id" => 2, "v" => "b" },
      { "id" => 3, "v" => "c" },
      { "id" => 4, "v" => "d" },
    ]
    new_rows = [
      { "id" => 3, "v" => "c2" },
      { "id" => 5, "v" => "e" },
      { "id" => 1, "v" => "a" },
      { "id" => 4, "v" => "d" },
    ]
    identity = ->(row) { row["id"] }
    patch = assert_round_trip(old_rows, new_rows, identity: identity)
    assert_equal [
      { "op" => "move", "from" => "/2", "path" => "/0" },
      { "op" => "replace", "path" => "/0/v", "value" => "c2" },
      { "op" => "add", "path" => "/1", "value" => { "id" => 5, "v" => "e" } },
      { "op" => "move", "from" => "/4", "path" => "/3" },
      { "op" => "remove", "path" => "/4" },
    ], patch
  end

  def test_identity_in_nested_arrays
    identity = ->(row) { row.is_a?(Hash) ? row["id"] : nil }
    old_document = { "groups" => [
      { "id" => "g1", "items" => [{ "id" => 1 }, { "id" => 2 }] },
      { "id" => "g2", "items" => [] },
    ] }
    new_document = { "groups" => [
      { "id" => "g2", "items" => [{ "id" => 9 }] },
      { "id" => "g1", "items" => [{ "id" => 2 }, { "id" => 1 }] },
    ] }
    patch = assert_round_trip(old_document, new_document, identity: identity)
    assert patch.any? { |op| op["op"] == "move" }
  end

  def test_duplicate_identity_falls_back_to_positional
    identity = ->(row) { row["id"] }
    old_rows = [{ "id" => 1 }, { "id" => 1 }]
    new_rows = [{ "id" => 1 }]
    patch = JSON::Diff.generate(old_rows, new_rows, identity: identity)
    assert_empty patch.select { |op| op["op"] == "move" }
    assert_equal new_rows, JSON::Diff.apply(old_rows, patch)
  end

  def test_nil_identity_falls_back_to_positional
    identity = ->(row) { row["id"] }
    old_rows = [{ "id" => 1 }, { "name" => "no id" }]
    new_rows = [{ "name" => "no id" }, { "id" => 1 }]
    patch = JSON::Diff.generate(old_rows, new_rows, identity: identity)
    assert_empty patch.select { |op| op["op"] == "move" }
    assert_equal new_rows, JSON::Diff.apply(old_rows, patch)
  end

  def test_round_trip_deeply_nested_mixed_document
    old_document = {
      "meta" => { "version" => 1, "tags" => ["a", "b"] },
      "users" => [
        { "id" => 1, "name" => "Ann", "roles" => ["admin"] },
        { "id" => 2, "name" => "Bob", "roles" => [] },
      ],
      "we/ird~key" => { "nested" => [true, nil, 1.5] },
    }
    new_document = {
      "meta" => { "version" => 2, "tags" => ["a", "b", "c"] },
      "users" => [
        { "id" => 2, "name" => "Bob", "roles" => ["user"] },
        { "id" => 3, "name" => "Cid", "roles" => [] },
        { "id" => 1, "name" => "Ann", "roles" => ["admin", "ops"] },
      ],
      "we/ird~key" => { "nested" => [true, nil, 1.5] },
      "added" => { "deep" => { "deeper" => [1, [2, [3]]] } },
    }
    identity = ->(row) { row.is_a?(Hash) ? row["id"] : nil }
    assert_round_trip(old_document, new_document, identity: identity)
    assert_round_trip(old_document, new_document)
  end

  def test_round_trip_via_json_serialization
    old_document = JSON.parse(JSON.generate({ "a" => [1, 2, 3], "b" => { "c" => "d" } }))
    new_document = JSON.parse(JSON.generate({ "a" => [3, 2], "b" => { "c" => "e" }, "f" => nil }))
    patch = JSON::Diff.generate(old_document, new_document)
    serialized = JSON.parse(JSON.generate(patch))
    assert_equal new_document, JSON::Diff.apply(old_document, serialized)
  end

  def test_apply_does_not_mutate_inputs
    old_document = { "list" => [1, 2, 3] }
    patch = JSON::Diff.generate(old_document, { "list" => [1, 2, 3, 4] })
    frozen_copy = Marshal.load(Marshal.dump(old_document))
    JSON::Diff.apply(old_document, patch)
    assert_equal frozen_copy, old_document
  end

  def test_apply_move_and_root_replace
    assert_equal [2, 1], JSON::Diff.apply([1, 2], [{ "op" => "move", "from" => "/1", "path" => "/0" }])
    assert_equal({ "x" => 1 }, JSON::Diff.apply([1, 2], [{ "op" => "replace", "path" => "", "value" => { "x" => 1 } }]))
  end

  def test_apply_rejects_invalid_paths
    assert_raise(JSON::Diff::PatchError) do
      JSON::Diff.apply([1], [{ "op" => "remove", "path" => "/5" }])
    end
    assert_raise(JSON::Diff::PatchError) do
      JSON::Diff.apply({ "a" => 1 }, [{ "op" => "remove", "path" => "/b" }])
    end
    assert_raise(JSON::Diff::PatchError) do
      JSON::Diff.apply({}, [{ "op" => "explode", "path" => "" }])
    end
  end

  def test_patch_is_smaller_than_full_replace
    old_document = {
      "records" => (1..100).map { |n| { "id" => n, "value" => "row #{n}" } },
    }
    new_records = old_document["records"].map(&:dup)
    moved = new_records.delete_at(49)
    moved["value"] = "edited"
    new_records.insert(10, moved)
    new_document = { "records" => new_records }

    identity = ->(row) { row["id"] }
    patch = JSON::Diff.generate(old_document, new_document, identity: identity)
    full_replace = [{ "op" => "replace", "path" => "", "value" => new_document }]

    assert_equal [
      { "op" => "move", "from" => "/records/49", "path" => "/records/10" },
      { "op" => "replace", "path" => "/records/10/value", "value" => "edited" },
    ], patch
    assert_operator patch.length, :<, full_replace.length + 2
    assert_operator JSON.generate(patch).bytesize, :<, JSON.generate(full_replace).bytesize / 10
    assert_equal new_document, JSON::Diff.apply(old_document, patch)
  end
end
