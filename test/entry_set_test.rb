# frozen_string_literal: true

require_relative 'test_helper'

class ZipEntrySetTest < Minitest::Test
  ZIP_ENTRIES = [
    ::Zip::Entry.new('zipfile.zip', 'name1', comment: 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name3', comment: 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name2', comment: 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name4', comment: 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name5', comment: 'comment1'),
    ::Zip::Entry.new('zipfile.zip', 'name6', comment: 'comment1')
  ].freeze

  def setup
    @zip_entry_set = ::Zip::EntrySet.new(ZIP_ENTRIES)
  end

  def teardown
    ::Zip.reset!
  end

  def test_include
    assert(@zip_entry_set.include?(ZIP_ENTRIES.first))
    assert(
      !@zip_entry_set.include?(
        ::Zip::Entry.new('different.zip', 'different', comment: 'aComment')
      )
    )
  end

  def test_size
    assert_equal(ZIP_ENTRIES.size, @zip_entry_set.size)
    assert_equal(ZIP_ENTRIES.size, @zip_entry_set.length)
    @zip_entry_set << ::Zip::Entry.new('a', 'b', comment: 'c')
    assert_equal(ZIP_ENTRIES.size + 1, @zip_entry_set.length)
  end

  def test_add
    zes = ::Zip::EntrySet.new
    entry1 = ::Zip::Entry.new('zf.zip', 'name1')
    entry2 = ::Zip::Entry.new('zf.zip', 'name2')
    zes << entry1
    assert(zes.include?(entry1))
    zes.push(entry2)
    assert(zes.include?(entry2))
  end

  def test_delete
    assert_equal(ZIP_ENTRIES.size, @zip_entry_set.size)
    entry = @zip_entry_set.delete(ZIP_ENTRIES.first)
    assert_equal(ZIP_ENTRIES.size - 1, @zip_entry_set.size)
    assert_equal(ZIP_ENTRIES.first, entry)

    entry = @zip_entry_set.delete(ZIP_ENTRIES.first)
    assert_equal(ZIP_ENTRIES.size - 1, @zip_entry_set.size)
    assert_nil(entry)
  end

  def test_each
    # Used each instead each_with_index due the bug in jRuby
    count = 0
    new_size = 200
    @zip_entry_set.each do |entry|
      assert(ZIP_ENTRIES.include?(entry))
      entry.clean_up # Start from a "saved" state.
      entry.size = new_size # Check that entries can be changed in this block.
      count += 1
    end

    assert_equal(ZIP_ENTRIES.size, count)
    @zip_entry_set.each do |entry|
      assert_equal(new_size, entry.size)
      assert(entry.dirty?) # Size was changed.
    end
  end

  def test_entries
    assert_equal(ZIP_ENTRIES, @zip_entry_set.entries)
  end

  def test_find_entry
    entries = [
      ::Zip::Entry.new('zipfile.zip', 'MiXeDcAsEnAmE', comment: 'comment1')
    ]

    ::Zip.case_insensitive_match = true
    zip_entry_set = ::Zip::EntrySet.new(entries)
    assert_equal(entries[0], zip_entry_set.find_entry('MiXeDcAsEnAmE'))
    assert_equal(entries[0], zip_entry_set.find_entry('mixedcasename'))

    ::Zip.case_insensitive_match = false
    zip_entry_set = ::Zip::EntrySet.new(entries)
    assert_equal(entries[0], zip_entry_set.find_entry('MiXeDcAsEnAmE'))
    assert_nil(zip_entry_set.find_entry('mixedcasename'))
  end

  def test_entries_with_sort
    ::Zip.sort_entries = true
    assert_equal(ZIP_ENTRIES.sort, @zip_entry_set.entries)
    ::Zip.sort_entries = false
    assert_equal(ZIP_ENTRIES, @zip_entry_set.entries)
  end

  # In this test we really are testing `#each`, hence the need to disable the cop.
  def test_entries_sorted_in_each
    ::Zip.sort_entries = true
    arr = []
    @zip_entry_set.each do |entry| # rubocop:disable Style/MapIntoArray
      arr << entry
    end
    assert_equal(ZIP_ENTRIES.sort, arr)

    # Ensure `each` above hasn't permanently altered the ordering.
    ::Zip.sort_entries = false
    arr = []
    @zip_entry_set.each do |entry| # rubocop:disable Style/MapIntoArray
      arr << entry
    end
    assert_equal(ZIP_ENTRIES, arr)
  end

  def test_compound
    new_entry = ::Zip::Entry.new(
      'zf.zip', 'new entry', comment: "new entry's comment"
    )
    assert_equal(ZIP_ENTRIES.size, @zip_entry_set.size)
    @zip_entry_set << new_entry
    assert_equal(ZIP_ENTRIES.size + 1, @zip_entry_set.size)
    assert(@zip_entry_set.include?(new_entry))

    @zip_entry_set.delete(new_entry)
    assert_equal(ZIP_ENTRIES.size, @zip_entry_set.size)
  end

  def test_dup
    copy = @zip_entry_set.dup
    assert_equal(@zip_entry_set, copy)

    # demonstrate that this is a deep copy
    copy.entries[0].name = 'a totally different name'
    assert(@zip_entry_set != copy)
  end

  def test_parent
    entries = [
      ::Zip::Entry.new('zf.zip', 'a/'),
      ::Zip::Entry.new('zf.zip', 'a/b/'),
      ::Zip::Entry.new('zf.zip', 'a/b/c/')
    ]
    entry_set = ::Zip::EntrySet.new(entries)

    assert_nil(entry_set.parent(entries[0]))
    assert_equal(entries[0], entry_set.parent(entries[1]))
    assert_equal(entries[1], entry_set.parent(entries[2]))
  end

  def test_glob
    res = @zip_entry_set.glob('name[2-4]')
    assert_equal(3, res.size)
    assert_equal(ZIP_ENTRIES[1, 3].sort, res.sort)
  end

  def test_glob2
    entries = [
      ::Zip::Entry.new('zf.zip', 'a/'),
      ::Zip::Entry.new('zf.zip', 'a/b/b1'),
      ::Zip::Entry.new('zf.zip', 'a/b/c/'),
      ::Zip::Entry.new('zf.zip', 'a/b/c/c1')
    ]
    entry_set = ::Zip::EntrySet.new(entries)

    assert_equal(entries[0, 1], entry_set.glob('*'))
    # assert_equal(entries[FIXME], entry_set.glob("**"))
    # res = entry_set.glob('a*')
    # assert_equal(entries.size, res.size)
    # assert_equal(entry_set.map { |e| e.name }, res.map { |e| e.name })
  end

  def test_glob3
    entries = [
      ::Zip::Entry.new('zf.zip', 'a/a'),
      ::Zip::Entry.new('zf.zip', 'a/b'),
      ::Zip::Entry.new('zf.zip', 'a/c')
    ]
    entry_set = ::Zip::EntrySet.new(entries)

    assert_equal(entries[0, 2].sort, entry_set.glob('a/{a,b}').sort)
  end

  def test_push_overwrites_by_default
    zes = Zip::EntrySet.new
    entry1 = Zip::Entry.new('zf.zip', 'name1', comment: 'first')
    entry2 = Zip::Entry.new('zf.zip', 'name1', comment: 'second')
    zes << entry1
    zes << entry2

    assert_equal(1, zes.size)
    assert_equal(entry2, zes.find_entry('name1'))
  end

  def test_push_appends_when_duplicates_allowed
    Zip.allow_duplicate_entry_names = true

    zes = Zip::EntrySet.new
    entry1 = Zip::Entry.new('zf.zip', 'name1', comment: 'first')
    entry2 = Zip::Entry.new('zf.zip', 'name1', comment: 'second')
    zes << entry1
    zes << entry2

    assert_equal(2, zes.size)
    assert_equal([entry1, entry2], zes.find_entry('name1'))
  end

  def test_find_entry_returns_array_when_duplicates_allowed
    Zip.allow_duplicate_entry_names = true

    zes = Zip::EntrySet.new(ZIP_ENTRIES)
    assert_equal([ZIP_ENTRIES.first], zes.find_entry(ZIP_ENTRIES.first.name))
    assert_equal([], zes.find_entry('does-not-exist'))
  end

  def test_size_counts_entries_not_names_when_duplicates_allowed
    Zip.allow_duplicate_entry_names = true

    zes = Zip::EntrySet.new(ZIP_ENTRIES)
    assert_equal(ZIP_ENTRIES.size, zes.size)
    zes << Zip::Entry.new('zf.zip', ZIP_ENTRIES.first.name, comment: 'dup')
    assert_equal(ZIP_ENTRIES.size + 1, zes.size)
  end

  def test_delete_removes_only_the_given_duplicate
    Zip.allow_duplicate_entry_names = true

    # Two entries that are attribute-identical (Entry#== is content-based,
    # not identity-based), so `Array#delete` would remove both instead of
    # just the one requested.
    entry1 = Zip::Entry.new('zf.zip', 'name1', comment: 'same')
    entry2 = Zip::Entry.new('zf.zip', 'name1', comment: 'same')
    assert_equal(entry1, entry2)

    zes = Zip::EntrySet.new([entry1, entry2])
    assert_equal(2, zes.size)

    removed = zes.delete(entry1)
    assert_equal(entry1, removed)
    assert_equal(1, zes.size)
    assert_equal([entry2], zes.find_entry('name1'))
  end

  def test_delete_removes_key_once_bucket_is_empty
    Zip.allow_duplicate_entry_names = true

    entry = Zip::Entry.new('zf.zip', 'name1')
    zes = Zip::EntrySet.new([entry])
    zes.delete(entry)

    refute(zes.include?(entry))
    assert_equal([], zes.find_entry('name1'))
  end

  def test_entries_flattened_with_duplicates
    Zip.allow_duplicate_entry_names = true

    dup_entry = Zip::Entry.new('zf.zip', ZIP_ENTRIES.first.name, comment: 'dup')
    zes = Zip::EntrySet.new(ZIP_ENTRIES + [dup_entry])

    assert_equal(ZIP_ENTRIES.size + 1, zes.entries.size)
    assert(zes.entries.include?(dup_entry))
  end

  def test_delete_matches_by_name_only_when_duplicates_not_allowed
    # Regression test: delete must still work by name alone (not requiring
    # object identity or attribute equality) when duplicates aren't allowed,
    # matching pre-existing behavior - only once duplicates are allowed is
    # there more than one candidate per name to disambiguate between.
    stored = Zip::Entry.new('zf.zip', 'name1', size: 100, crc: 111)
    zes = Zip::EntrySet.new([stored])

    lookalike = Zip::Entry.new('zf.zip', 'name1', size: 999, crc: 222)
    refute_equal(lookalike, stored)

    removed = zes.delete(lookalike)
    assert_equal(stored, removed)
    refute(zes.include?('name1'))
  end

  def test_dup_preserves_insertion_order_regardless_of_sort_entries
    entry1 = Zip::Entry.new('zf.zip', 'zzz.txt')
    entry2 = Zip::Entry.new('zf.zip', 'aaa.txt')
    zes = Zip::EntrySet.new([entry1, entry2])

    Zip.sort_entries = true
    copy = zes.dup
    Zip.sort_entries = false

    assert_equal(zes.entries.map(&:name), copy.entries.map(&:name))
  end

  def test_dup_with_duplicates
    Zip.allow_duplicate_entry_names = true

    dup_entry = Zip::Entry.new('zf.zip', ZIP_ENTRIES.first.name, comment: 'dup')
    zes = Zip::EntrySet.new(ZIP_ENTRIES + [dup_entry])
    copy = zes.dup

    assert_equal(zes, copy)

    # demonstrate that this is a deep copy
    copy.entries.first.name = 'a totally different name'
    assert(zes != copy)
  end
end
