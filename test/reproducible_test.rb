# frozen_string_literal: true

require 'fileutils'
require 'find'

require_relative 'test_helper'

class ReproducibleTest < Minitest::Test
  def test_file_archives_are_byte_for_byte_reproducible
    Dir.mktmpdir do |tmp|
      first_source = File.join(tmp, 'source-a')
      second_source = File.join(tmp, 'source-b')
      first_zip = File.join(tmp, 'first.zip')
      second_zip = File.join(tmp, 'second.zip')

      apply_umask(0o022) do
        create_source_tree(first_source, Time.local(2020, 1, 2, 3, 4, 6),
                           file_mode: 0o600, directory_mode: 0o700)
        create_archive(first_zip, first_source, REVERSED_ENTRIES)
      end

      apply_umask(0o077) do
        create_source_tree(second_source, Time.local(2021, 2, 3, 4, 5, 8),
                           file_mode: 0o755, directory_mode: 0o750)
        create_archive(second_zip, second_source, FORWARD_ENTRIES)
      end

      assert_equal(File.binread(first_zip), File.binread(second_zip))
      assert_reproducible_entries(first_zip)
      assert_extracted_contents(first_zip, second_zip)
    end
  end

  def test_default_mode_preserves_source_metadata_and_insertion_order
    Dir.mktmpdir do |tmp|
      first_source = File.join(tmp, 'source-a')
      second_source = File.join(tmp, 'source-b')
      first_zip = File.join(tmp, 'first.zip')
      second_zip = File.join(tmp, 'second.zip')

      create_source_tree(first_source, Time.local(2020, 1, 2, 3, 4, 6),
                         file_mode: 0o600, directory_mode: 0o700)
      create_source_tree(second_source, Time.local(2021, 2, 3, 4, 5, 8),
                         file_mode: 0o755, directory_mode: 0o750)
      create_archive(first_zip, first_source, REVERSED_ENTRIES, reproducible: false)
      create_archive(second_zip, second_source, FORWARD_ENTRIES, reproducible: false)

      refute_equal(File.binread(first_zip), File.binread(second_zip))

      Zip::File.open(first_zip) do |zip|
        assert_equal(REVERSED_ENTRIES, zip.entries.map(&:name))
        assert_equal(0o600, zip.find_entry('a.txt').unix_perms)
        assert_equal(0o700, zip.find_entry('dir/').unix_perms)
        assert(zip.find_entry('link').symlink?)
      end
    end
  end

  def test_normalization_can_be_disabled_explicitly
    Dir.mktmpdir do |tmp|
      source = File.join(tmp, 'source')
      zip_path = File.join(tmp, 'archive.zip')
      create_source_tree(source, Time.local(2020, 1, 2, 3, 4, 6),
                         file_mode: 0o600, directory_mode: 0o700)

      create_archive(
        zip_path, source, REVERSED_ENTRIES,
        reproducible: {
          sort_entries: false,
          time: false,
          permissions: false,
          fstype: false,
          extra_fields: false
        }
      )

      Zip::File.open(zip_path) do |zip|
        assert_equal(REVERSED_ENTRIES, zip.entries.map(&:name))
        assert_equal(0o600, zip.find_entry('a.txt').unix_perms)
        assert_equal(0o700, zip.find_entry('dir/').unix_perms)
        assert_equal(2020, zip.find_entry('a.txt').mtime.year)
      end
    end
  end

  def test_explicit_insertion_order_overrides_global_entry_sorting
    Zip.sort_entries = true

    Dir.mktmpdir do |tmp|
      source = File.join(tmp, 'source')
      zip_path = File.join(tmp, 'archive.zip')
      create_source_tree(source, Time.local(2020, 1, 2, 3, 4, 6),
                         file_mode: 0o600, directory_mode: 0o700)

      create_archive(
        zip_path, source, REVERSED_ENTRIES,
        reproducible: { sort_entries: false }
      )
      Zip.sort_entries = false

      Zip::File.open(zip_path) do |zip|
        assert_equal(REVERSED_ENTRIES, zip.entries.map(&:name))
      end
    end
  ensure
    Zip.sort_entries = false
  end

  def test_output_stream_removes_non_essential_extra_fields
    buffer = Zip::OutputStream.write_buffer(reproducible: true) do |output|
      entry = Zip::Entry.new(nil, 'a.txt', time: Time.local(2020, 1, 2))
      entry.atime = Time.local(2020, 1, 3)
      output.put_next_entry(entry)
      output.write('a')

      output.put_next_entry('b.txt')
      output.write('b')
    end

    buffer.rewind
    Zip::File.open_buffer(buffer) do |zip|
      first_entry = zip.find_entry('a.txt')
      assert_equal('a.txt', first_entry.name)
      refute(first_entry.absolute_time?)
      assert_equal(1980, first_entry.mtime.year)
      assert_equal(Zip::FSTYPE_UNIX, first_entry.fstype)
      assert_equal(0o644, first_entry.unix_perms)

      second_entry = zip.find_entry('b.txt')
      assert_equal('b.txt', second_entry.name)
      assert_equal(0o644, second_entry.unix_perms)
    end
  end

  def test_reproducible_output_stream_supports_stored_entries
    buffer = Zip::OutputStream.write_buffer(reproducible: true) do |output|
      output.put_next_entry('z.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
      output.write('z')
      output.put_next_entry('a.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
      output.write('a')
    end

    buffer.rewind
    Zip::File.open_buffer(buffer) do |zip|
      assert_equal(['a.txt', 'z.txt'], zip.entries.map(&:name))
      assert(zip.entries.all? { |entry| entry.compression_method == Zip::Entry::STORED })
      assert_equal('a', zip.read('a.txt'))
      assert_equal('z', zip.read('z.txt'))
    end
  end

  def test_reproducible_file_rewrites_existing_entries_in_sorted_order
    Dir.mktmpdir do |tmp|
      source_zip = File.join(tmp, 'source.zip')
      deterministic_zip = File.join(tmp, 'deterministic.zip')

      Zip::File.open(source_zip, create: true) do |zip|
        zip.get_output_stream('b.txt') { |stream| stream.write('b') }
        zip.get_output_stream('a.txt') { |stream| stream.write('a') }
      end

      Zip::File.open(source_zip, reproducible: true) { |zip| zip.comment = 'x' }
      FileUtils.cp(source_zip, deterministic_zip)
      Zip::File.open(deterministic_zip, reproducible: true) { |zip| zip.comment = 'x' }

      assert_equal(File.binread(source_zip), File.binread(deterministic_zip))
      Zip::File.open(source_zip) do |zip|
        assert_equal(['a.txt', 'b.txt'], zip.entries.map(&:name))
        assert_equal('a', zip.read('a.txt'))
        assert_equal('b', zip.read('b.txt'))
      end
    end
  end

  def test_reproducible_output_stream_rejects_encryption
    encrypter = Zip::TraditionalEncrypter.new('password')

    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(encrypter: encrypter, reproducible: true) {}
    end
    assert_match(/encryption/i, error.message)
  end

  def test_unknown_reproducible_option_is_rejected
    error = assert_raises(ArgumentError) do
      Zip::OutputStream.write_buffer(reproducible: { timestamps: true }) {}
    end
    assert_equal('Unknown reproducible option: :timestamps', error.message)
  end

  private

  FORWARD_ENTRIES = ['a.txt', 'b.txt', 'dir/', 'dir/c.txt', 'link'].freeze
  REVERSED_ENTRIES = FORWARD_ENTRIES.reverse.freeze

  def create_source_tree(root, mtime, file_mode:, directory_mode:)
    FileUtils.mkdir_p(File.join(root, 'dir'))
    File.write(File.join(root, 'a.txt'), 'a')
    File.write(File.join(root, 'b.txt'), 'b')
    File.write(File.join(root, 'dir', 'c.txt'), 'c')
    File.symlink('a.txt', File.join(root, 'link'))

    Find.find(root) do |path|
      next if path == root

      FileUtils.touch(path, mtime: mtime)
      if File.directory?(path)
        File.chmod(directory_mode, path)
      elsif File.file?(path)
        File.chmod(file_mode, path)
      end
    end
  end

  def create_archive(zip_path, source, entry_names, reproducible: true)
    Zip::File.open(zip_path, create: true, reproducible: reproducible) do |zip|
      entry_names.each do |entry_name|
        zip.add(entry_name, File.join(source, entry_name))
      end
    end
  end

  def assert_reproducible_entries(zip_path)
    Zip::File.open(zip_path) do |zip|
      assert_equal(FORWARD_ENTRIES, zip.entries.map(&:name))

      ["a.txt", "b.txt", "dir/c.txt"].each do |name|
        entry = zip.find_entry(name)
        assert_equal(Zip::FSTYPE_UNIX, entry.fstype)
        assert_equal(0o644, entry.unix_perms)
        assert_equal(1980, entry.mtime.year)
        assert_equal(1, entry.mtime.month)
        assert_equal(1, entry.mtime.day)
        assert_equal(0, entry.mtime.hour)
        assert_equal(0, entry.mtime.min)
        assert_equal(0, entry.mtime.sec)
      end

      directory = zip.find_entry('dir/')
      assert(directory.directory?)
      assert_equal(0o755, directory.unix_perms)

      symlink = zip.find_entry('link')
      assert(symlink.symlink?)
      refute(symlink.file?)
      assert_equal(0o777, symlink.unix_perms)
      assert_equal('a.txt', zip.read('link'))
    end
  end

  def assert_extracted_contents(first_zip, second_zip)
    Dir.mktmpdir do |first_dir|
      Dir.mktmpdir do |second_dir|
        Zip::File.open(first_zip) { |zip| zip.extract_all(first_dir) }
        Zip::File.open(second_zip) { |zip| zip.extract_all(second_dir) }

        %w[a.txt b.txt dir/c.txt].each do |name|
          assert_equal(File.read(File.join(first_dir, name)),
                       File.read(File.join(second_dir, name)))
        end
      end
    end
  end

  def apply_umask(umask)
    previous_umask = File.umask(umask)
    yield
  ensure
    File.umask(previous_umask)
  end
end
