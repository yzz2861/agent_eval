# frozen_string_literal: true

require_relative 'test_helper'
require 'json/patch'

class JSONPatchTest < Test::Unit::TestCase
  def relocate(document, first_patch, second_patch)
    JSON::Patch.relocate(document, first_patch, second_patch)
  end

  def test_relocates_successive_array_insertions_and_removals
    document = {
      'items' => [
        { 'id' => 'a' },
        { 'id' => 'b' },
        { 'id' => 'c' },
        { 'id' => 'd' }
      ]
    }
    first_patch = [
      { 'op' => 'add', 'path' => '/items/0', 'value' => { 'id' => 'p0' } },
      { 'op' => 'add', 'path' => '/items/3', 'value' => { 'id' => 'p3' } },
      { 'op' => 'remove', 'path' => '/items/5' }
    ]
    second_patch = [
      { 'op' => 'add', 'path' => '/items/1', 'value' => { 'id' => 'q1' } },
      { 'op' => 'add', 'path' => '/items/4', 'value' => { 'id' => 'q4' } },
      { 'op' => 'remove', 'path' => '/items/2' }
    ]

    result = relocate(document, first_patch, second_patch)

    expected_paths = %w[/items/2 /items/6 /items/3]
    assert_equal expected_paths, result.patch.map { |operation| operation['path'] }
    assert result.success?
    assert_equal(
      [
        { 'id' => 'p0' },
        { 'id' => 'a' },
        { 'id' => 'q1' },
        { 'id' => 'p3' },
        { 'id' => 'c' },
        { 'id' => 'q4' }
      ],
      JSON::Patch.apply(JSON::Patch.apply(document, first_patch), result.patch)['items']
    )
  end

  def test_relocates_array_move_with_evolving_indices
    document = { 'items' => %w[a b c d e] }
    first_patch = [
      { 'op' => 'remove', 'path' => '/items/1' },
      { 'op' => 'add', 'path' => '/items/0', 'value' => 'p' }
    ]
    second_patch = [
      { 'op' => 'move', 'from' => '/items/3', 'path' => '/items/1' },
      { 'op' => 'move', 'from' => '/items/4', 'path' => '/items/1' }
    ]

    result = relocate(document, first_patch, second_patch)

    assert_equal(
      [
        { 'op' => 'move', 'from' => '/items/3', 'path' => '/items/2' },
        { 'op' => 'move', 'from' => '/items/4', 'path' => '/items/2' }
      ],
      result.patch
    )
    merged = JSON::Patch.apply(JSON::Patch.apply(document, first_patch), result.patch)
    assert_equal({ 'items' => %w[p a e d c] }, merged)
  end

  def test_reports_conflict_when_ancestor_is_deleted
    document = { 'parent' => { 'child' => { 'name' => 'keep' } } }
    first_patch = [{ 'op' => 'remove', 'path' => '/parent' }]
    second_patch = [{ 'op' => 'replace', 'path' => '/parent/child/name', 'value' => 'x' }]

    result = relocate(document, first_patch, second_patch)

    refute result.success?
    assert_equal [], result.patch
    assert_equal 0, result.conflicts.first.operation
    assert_equal 'ancestor_deleted', result.conflicts.first.code
  end

  def test_reports_conflict_when_move_source_has_changed
    document = { 'source' => { 'name' => 'old' }, 'target' => nil }
    first_patch = [{ 'op' => 'replace', 'path' => '/source/name', 'value' => 'new' }]
    second_patch = [{ 'op' => 'move', 'from' => '/source', 'path' => '/target' }]

    result = relocate(document, first_patch, second_patch)

    refute result.success?
    assert_equal 'source_changed', result.conflicts.first.code
    assert_equal '/source', result.conflicts.first.from
  end

  def test_relocates_through_moved_ancestor
    document = { 'a' => { 'b' => 1 } }
    first_patch = [{ 'op' => 'move', 'from' => '/a', 'path' => '/z' }]
    second_patch = [{ 'op' => 'replace', 'path' => '/a/b', 'value' => 2 }]

    result = relocate(document, first_patch, second_patch)

    assert result.success?
    assert_equal '/z/b', result.patch.dig(0, 'path')
  end

  def test_reports_conflict_for_copy_of_changed_source
    document = { 'source' => { 'name' => 'old' } }
    first_patch = [{ 'op' => 'replace', 'path' => '/source/name', 'value' => 'new' }]
    second_patch = [{ 'op' => 'copy', 'from' => '/source', 'path' => '/copy' }]

    result = relocate(document, first_patch, second_patch)

    refute result.success?
    assert_equal 'source_changed', result.conflicts.first.code
  end

  def test_reports_conflict_for_object_key_added_by_first_patch
    document = {}
    first_patch = [{ 'op' => 'add', 'path' => '/name', 'value' => 'first' }]
    second_patch = [{ 'op' => 'add', 'path' => '/name', 'value' => 'second' }]

    result = relocate(document, first_patch, second_patch)

    refute result.success?
    assert_equal 'target_occupied', result.conflicts.first.code
  end

  def test_reports_conflict_for_same_value_replacement
    document = { 'name' => 'same' }
    first_patch = [{ 'op' => 'replace', 'path' => '/name', 'value' => 'first' }]
    second_patch = [{ 'op' => 'replace', 'path' => '/name', 'value' => 'second' }]

    result = relocate(document, first_patch, second_patch)

    refute result.success?
    assert_equal 'target_changed', result.conflicts.first.code
  end

  def test_relocates_test_through_unmodified_move
    document = { 'items' => [{ 'name' => 'a' }, { 'name' => 'b' }] }
    first_patch = [{ 'op' => 'move', 'from' => '/items/0', 'path' => '/items/-' }]
    second_patch = [{ 'op' => 'test', 'path' => '/items/0/name', 'value' => 'a' }]

    result = relocate(document, first_patch, second_patch)

    assert result.success?
    assert_equal '/items/1/name', result.patch.dig(0, 'path')
  end

  def test_applies_all_supported_operations
    document = {
      'items' => [1, 2, 3],
      'member' => { 'kept' => true },
      'value' => 'old',
      'source' => 'copied'
    }
    patch = [
      { 'op' => 'add', 'path' => '/items/1', 'value' => 9 },
      { 'op' => 'remove', 'path' => '/member/kept' },
      { 'op' => 'replace', 'path' => '/value', 'value' => 'new' },
      { 'op' => 'move', 'from' => '/items/0', 'path' => '/items/-' },
      { 'op' => 'copy', 'from' => '/source', 'path' => '/source-copy' },
      { 'op' => 'test', 'path' => '/value', 'value' => 'new' }
    ]

    assert_equal(
      {
        'items' => [9, 2, 3, 1],
        'member' => {},
        'value' => 'new',
        'source' => 'copied',
        'source-copy' => 'copied'
      },
      JSON::Patch.apply(document, patch)
    )
  end

  def test_replaces_and_adds_root_document
    assert_equal [2], JSON::Patch.apply([1], [{ 'op' => 'replace', 'path' => '', 'value' => [2] }])
    result = JSON::Patch.apply({}, [{ 'op' => 'add', 'path' => '', 'value' => { 'name' => 'new' } }])
    assert_equal({ 'name' => 'new' }, result)
  end
end
