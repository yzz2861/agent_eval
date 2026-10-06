# frozen_string_literal: true

require_relative 'test_helper'

class JSONPatchTest < Test::Unit::TestCase
  ID_BY_ID = ->(element) { element["id"] }

  def assert_round_trip(old_document, new_document, array_identity: nil)
    patch = JSON::Patch.diff(old_document, new_document, array_identity: array_identity)
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))
    patch
  end

  def test_identical_documents_produce_empty_patch
    document = { "a" => [1, { "b" => "c" }], "d" => nil }
    assert_equal([], JSON::Patch.diff(document, document))
    assert_equal([], JSON::Patch.diff(document, JSON.parse(JSON.generate(document))))
  end

  def test_root_scalar_replace
    patch = JSON::Patch.diff(1, 2)
    assert_equal([{ "op" => "replace", "path" => "", "value" => 2 }], patch)
    assert_equal(2, JSON::Patch.apply(1, patch))
  end

  def test_root_type_change_replaces_whole_document
    patch = JSON::Patch.diff({ "a" => 1 }, [1, 2])
    assert_equal([{ "op" => "replace", "path" => "", "value" => [1, 2] }], patch)
    assert_equal([1, 2], JSON::Patch.apply({ "a" => 1 }, patch))
  end

  def test_integer_and_float_are_not_confused
    patch = JSON::Patch.diff({ "n" => 1 }, { "n" => 1.0 })
    assert_equal([{ "op" => "replace", "path" => "/n", "value" => 1.0 }], patch)
  end

  def test_hash_add_remove_replace
    old_document = { "keep" => 1, "change" => 2, "drop" => 3 }
    new_document = { "keep" => 1, "change" => 20, "add" => 30 }
    patch = JSON::Patch.diff(old_document, new_document)
    assert_equal([
      { "op" => "remove", "path" => "/drop" },
      { "op" => "replace", "path" => "/change", "value" => 20 },
      { "op" => "add", "path" => "/add", "value" => 30 },
    ], patch)
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))
  end

  def test_pointer_escaping
    old_document = { "a/b" => 1, "c~d" => 2, "~0/x~1" => { "y/z" => 3 } }
    new_document = { "a/b" => 10, "c~d" => 2, "~0/x~1" => { "y/z" => 30 } }
    patch = JSON::Patch.diff(old_document, new_document)
    assert_equal([
      { "op" => "replace", "path" => "/a~1b", "value" => 10 },
      { "op" => "replace", "path" => "/~00~1x~01/y~1z", "value" => 30 },
    ], patch)
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))
  end

  def test_array_append_is_a_single_add
    patch = JSON::Patch.diff([1, 2, 3], [1, 2, 3, 4])
    assert_equal([{ "op" => "add", "path" => "/3", "value" => 4 }], patch)
  end

  def test_array_prepend_is_a_single_add
    patch = JSON::Patch.diff([1, 2, 3], [0, 1, 2, 3])
    assert_equal([{ "op" => "add", "path" => "/0", "value" => 0 }], patch)
  end

  def test_array_removal_in_the_middle
    patch = JSON::Patch.diff([1, 2, 3], [1, 3])
    assert_equal([{ "op" => "remove", "path" => "/1" }], patch)
  end

  def test_array_element_edit_does_not_replace_whole_array
    old_document = { "items" => [{ "a" => 1 }, { "b" => 2 }, { "c" => 3 }] }
    new_document = { "items" => [{ "a" => 1 }, { "b" => 20 }, { "c" => 3 }] }
    patch = JSON::Patch.diff(old_document, new_document)
    assert_equal([{ "op" => "replace", "path" => "/items/1/b", "value" => 20 }], patch)
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))
  end

  def test_conservative_strategy_never_emits_move
    old_document = [1, 2, 3]
    new_document = [3, 2, 1]
    patch = JSON::Patch.diff(old_document, new_document)
    assert(patch.none? { |operation| operation["op"] == "move" })
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))
  end

  def test_conservative_strategy_multiple_removals_keep_indices_valid
    old_document = [1, 2, 3, 4, 5]
    new_document = [1, 5]
    patch = JSON::Patch.diff(old_document, new_document)
    assert_equal([
      { "op" => "remove", "path" => "/3" },
      { "op" => "remove", "path" => "/2" },
      { "op" => "remove", "path" => "/1" },
    ], patch)
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))
  end

  def test_identity_reorder_emits_only_moves
    old_document = [{ "id" => 1 }, { "id" => 2 }, { "id" => 3 }]
    new_document = [{ "id" => 3 }, { "id" => 1 }, { "id" => 2 }]
    patch = assert_round_trip(old_document, new_document, array_identity: ID_BY_ID)
    assert(patch.any? { |operation| operation["op"] == "move" })
    assert(patch.all? { |operation| operation["op"] == "move" })
  end

  def test_identity_move_and_edit
    old_document = {
      "users" => [
        { "id" => 1, "name" => "alice" },
        { "id" => 2, "name" => "bob" },
        { "id" => 3, "name" => "carol" },
      ]
    }
    new_document = {
      "users" => [
        { "id" => 3, "name" => "carol" },
        { "id" => 1, "name" => "Alice" },
        { "id" => 2, "name" => "bob" },
      ]
    }
    patch = assert_round_trip(old_document, new_document, array_identity: ID_BY_ID)
    assert_equal([
      { "op" => "move", "from" => "/users/2", "path" => "/users/0" },
      { "op" => "replace", "path" => "/users/1/name", "value" => "Alice" },
    ], patch)
  end

  def test_identity_add_and_remove
    old_document = [{ "id" => 1 }, { "id" => 2 }, { "id" => 3 }]
    new_document = [{ "id" => 3 }, { "id" => 4 }, { "id" => 1 }]
    patch = assert_round_trip(old_document, new_document, array_identity: ID_BY_ID)
    ops = patch.map { |operation| operation["op"] }
    assert_include(ops, "remove")
    assert_include(ops, "add")
    assert_include(ops, "move")
  end

  def test_identity_move_to_end
    old_document = [{ "id" => 1 }, { "id" => 2 }, { "id" => 3 }]
    new_document = [{ "id" => 2 }, { "id" => 3 }, { "id" => 1 }]
    patch = assert_round_trip(old_document, new_document, array_identity: ID_BY_ID)
    assert_equal([{ "op" => "move", "from" => "/0", "path" => "/2" }], patch)
  end

  def test_duplicate_identity_falls_back_to_conservative_strategy
    old_document = [{ "id" => 1, "v" => "a" }, { "id" => 1, "v" => "b" }]
    new_document = [{ "id" => 1, "v" => "b" }, { "id" => 1, "v" => "a" }]
    patch = assert_round_trip(old_document, new_document, array_identity: ID_BY_ID)
    assert(patch.none? { |operation| operation["op"] == "move" })
  end

  def test_nested_arrays_use_identity_recursively
    old_document = {
      "groups" => [
        { "id" => "g1", "members" => [{ "id" => 1 }, { "id" => 2 }] },
        { "id" => "g2", "members" => [] },
      ]
    }
    new_document = {
      "groups" => [
        { "id" => "g2", "members" => [] },
        { "id" => "g1", "members" => [{ "id" => 2 }, { "id" => 1 }] },
      ]
    }
    identity = ->(element) { element["id"] if element.is_a?(Hash) }
    patch = assert_round_trip(old_document, new_document, array_identity: identity)
    assert_equal([
      { "op" => "move", "from" => "/groups/0", "path" => "/groups/1" },
      { "op" => "move", "from" => "/groups/1/members/0", "path" => "/groups/1/members/1" },
    ], patch)
  end

  def test_apply_does_not_mutate_document_or_patch
    old_document = { "a" => [1, 2], "b" => { "c" => "d" } }
    new_document = { "a" => [1, 2, 3], "b" => { "c" => "e" } }
    patch = JSON::Patch.diff(old_document, new_document)
    frozen_document = JSON.parse(JSON.generate(old_document))
    frozen_patch = JSON.parse(JSON.generate(patch))
    result = JSON::Patch.apply(old_document, patch)
    assert_equal(new_document, result)
    assert_equal(frozen_document, old_document)
    assert_equal(frozen_patch, patch)
  end

  def test_apply_supports_symbol_keys_and_dash_append
    document = { "a" => [1] }
    patch = [
      { op: "add", path: "/a/-", value: 2 },
      { op: "replace", path: "/a/0", value: 0 },
    ]
    assert_equal({ "a" => [0, 2] }, JSON::Patch.apply(document, patch))
  end

  def test_apply_move_inside_same_array
    document = { "a" => %w[x y z] }
    patch = [{ "op" => "move", "from" => "/a/0", "path" => "/a/2" }]
    assert_equal({ "a" => %w[y z x] }, JSON::Patch.apply(document, patch))
  end

  def test_apply_errors
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({}, [{ "op" => "bogus", "path" => "" }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({}, [{ "op" => "add", "path" => "no-slash", "value" => 1 }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({}, [{ "op" => "remove", "path" => "/missing" }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply([], [{ "op" => "remove", "path" => "/0" }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({ "a" => [1] }, [{ "op" => "replace", "path" => "/a/5", "value" => 1 }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({ "a" => { "b" => 1 } }, [{ "op" => "move", "from" => "/a", "path" => "/a/b" }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({}, [{ "op" => "remove", "path" => "" }]) }
    assert_raise(JSON::Patch::Error) { JSON::Patch.apply({}, [{ "path" => "/a" }]) }
  end

  def test_complex_round_trip
    old_document = {
      "meta" => { "version" => 1, "tags" => %w[a b c] },
      "users" => [
        { "id" => 1, "roles" => %w[admin], "name" => "alice" },
        { "id" => 2, "roles" => %w[user], "name" => "bob" },
        { "id" => 3, "roles" => %w[user editor], "name" => "carol" },
      ],
      "weird/key" => { "tilde~" => [nil, true, 1.5] },
    }
    new_document = {
      "meta" => { "version" => 2, "tags" => %w[a c d] },
      "users" => [
        { "id" => 3, "roles" => %w[user editor admin], "name" => "carol" },
        { "id" => 1, "roles" => %w[admin], "name" => "Alice" },
        { "id" => 4, "roles" => [], "name" => "dave" },
      ],
      "weird/key" => { "tilde~" => [nil, true, 2.5] },
      "brand" => "new",
    }
    assert_round_trip(old_document, new_document, array_identity: ID_BY_ID)
    assert_round_trip(old_document, new_document)
  end

  def test_patch_is_smaller_than_full_replace
    old_document = {
      "users" => (1..50).map do |n|
        { "id" => n, "name" => "user-#{n}", "email" => "user#{n}@example.com" }
      end,
      "settings" => { "theme" => "dark", "locale" => "en", "features" => %w[a b c d e] },
    }
    new_users = old_document["users"].map(&:dup)
    new_users[10] = new_users[10].merge("name" => "renamed")
    new_users.insert(0, new_users.delete_at(30))
    new_document = {
      "users" => new_users,
      "settings" => { "theme" => "light", "locale" => "en", "features" => %w[a b c d e] },
    }
    patch = JSON::Patch.diff(old_document, new_document, array_identity: ID_BY_ID)
    assert_equal(new_document, JSON::Patch.apply(old_document, patch))

    full_replace = [{ "op" => "replace", "path" => "", "value" => new_document }]
    patch_size = JSON.generate(patch).bytesize
    full_size = JSON.generate(full_replace).bytesize
    assert_operator(patch.size, :<=, 5)
    assert_operator(patch_size, :<, full_size / 10)
  end
end
