# frozen_string_literal: true

require_relative 'test_helper'

class TransactionalExtractTest < Minitest::Test
  def setup
    @tmp = Dir.mktmpdir('rubyzip-tx-')
    @dest = File.join(@tmp, 'installed')
    @zip = File.join(@tmp, 'archive.zip')
    Zip.reset!
  end

  def teardown
    FileUtils.rm_rf(@tmp)
    Zip.reset!
  end

  def test_extracts_a_simple_archive
    build_zip(@zip) do |out|
      put_file(out, 'top.txt', 'top level')
      put_file(out, 'sub/nested.txt', 'nested')
      put_dir(out, 'empty/')
    end

    result = Zip::File.transactional_extract(@zip, @dest)

    assert_equal @dest, result
    assert_equal 'top level', File.read(File.join(@dest, 'top.txt'))
    assert_equal 'nested', File.read(File.join(@dest, 'sub', 'nested.txt'))
    assert File.directory?(File.join(@dest, 'empty'))
  end

  def test_extracts_symlinks_that_stay_inside_the_tree
    build_zip(@zip) do |out|
      put_file(out, 'target.txt', 'payload')
      put_symlink(out, 'link', 'target.txt')
      put_symlink(out, 'sub/chain_link', '../link')
    end

    Zip::File.transactional_extract(@zip, @dest)

    assert File.symlink?(File.join(@dest, 'link'))
    assert_equal 'target.txt', File.readlink(File.join(@dest, 'link'))
    assert File.symlink?(File.join(@dest, 'sub', 'chain_link'))
    assert_equal 'payload', File.read(File.join(@dest, 'sub', 'chain_link'))
  end

  def test_unix_permissions_are_restored
    build_zip(@zip) do |out|
      entry = Zip::Entry.new(@zip, 'exec.sh')
      entry.unix_perms = 0o754
      out.put_next_entry(entry)
      out.write('#!/bin/sh')
    end

    Zip::File.transactional_extract(@zip, @dest)

    assert_equal 0o100754, File.stat(File.join(@dest, 'exec.sh')).mode
  end

  def test_dangling_internal_symlinks_are_allowed
    build_zip(@zip) { |out| put_symlink(out, 'dangling', 'does-not-exist') }

    Zip::File.transactional_extract(@zip, @dest)

    link = File.join(@dest, 'dangling')
    assert File.symlink?(link)
    assert_equal 'does-not-exist', File.readlink(link)
  end

  def test_existing_destination_is_rejected_by_default
    build_zip(@zip) { |out| put_file(out, 'a.txt', 'a') }
    FileUtils.mkdir_p(@dest)
    original = File.join(@dest, 'keep.txt')
    File.write(original, 'do not touch')

    assert_raises(Zip::DestinationExistsError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    assert_equal 'do not touch', File.read(original)
  end

  def test_existing_destination_is_replaced_when_backup_requested
    build_zip(@zip) { |out| put_file(out, 'new.txt', 'new') }
    FileUtils.mkdir_p(@dest)
    File.write(File.join(@dest, 'old.txt'), 'old')

    Zip::File.transactional_extract(@zip, @dest, on_exist: :backup)

    assert_equal 'new', File.read(File.join(@dest, 'new.txt'))
    refute File.exist?(File.join(@dest, 'old.txt'))
    assert_empty leftover_backups
  end

  def test_unknown_on_exist_strategy_is_rejected
    build_zip(@zip) { |out| put_file(out, 'a.txt', 'a') }

    assert_raises(ArgumentError) do
      Zip::File.transactional_extract(@zip, @dest, on_exist: :clobber)
    end
  end

  def test_duplicate_entry_paths_are_rejected
    Zip.allow_duplicate_entry_names = true
    build_zip(@zip) do |out|
      put_file(out, 'same.txt', 'one')
      put_file(out, 'same.txt', 'two')
    end

    assert_raises(Zip::DuplicateEntryError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_case_folding_collisions_are_rejected
    build_zip(@zip) do |out|
      put_file(out, 'File.txt', 'one')
      put_file(out, 'FILE.TXT', 'two')
    end

    assert_raises(Zip::CaseInsensitiveMatchError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_file_directory_conflicts_are_rejected
    build_zip(@zip) do |out|
      put_file(out, 'a', 'i am a file')
      put_file(out, 'a/b', 'i need a directory')
    end

    assert_raises(Zip::EntryConflictError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_directory_file_conflicts_are_rejected
    Zip.allow_duplicate_entry_names = true
    build_zip(@zip) do |out|
      put_dir(out, 'a/')
      put_file(out, 'a', 'i am a file')
    end

    assert_raises(Zip::EntryConflictError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_entries_escaping_the_root_with_dot_dot_are_rejected
    build_zip(@zip) { |out| put_file(out, '../evil.txt', 'x') }

    assert_raises(Zip::EntryNameError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(File.join(@tmp, 'evil.txt'))
    refute File.exist?(@dest)
  end

  def test_absolute_entry_paths_are_rejected
    build_zip(@zip) { |out| put_raw_entry(out, '/etc/evil.txt', 'x') }

    assert_raises(Zip::EntryNameError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_embedded_dot_dot_paths_are_rejected
    build_zip(@zip) { |out| put_file(out, 'sub/../../evil.txt', 'x') }

    assert_raises(Zip::EntryNameError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(File.join(@tmp, 'evil.txt'))
    refute File.exist?(@dest)
  end

  def test_absolute_symlink_targets_are_rejected
    build_zip(@zip) do |out|
      put_file(out, 'a.txt', 'a')
      put_symlink(out, 'evil', '/etc/hosts')
    end

    assert_raises(Zip::SymlinkEscapeError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_symlink_targets_escaping_via_dot_dot_are_rejected
    build_zip(@zip) do |out|
      put_file(out, 'deep/a.txt', 'a')
      put_symlink(out, 'deep/evil', '../../outside')
    end

    assert_raises(Zip::SymlinkEscapeError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_symlink_chains_escaping_the_root_are_rejected
    build_zip(@zip) do |out|
      put_symlink(out, 'a', 'b')
      put_symlink(out, 'b', '../escape')
    end

    assert_raises(Zip::SymlinkEscapeError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    refute File.exist?(@dest)
  end

  def test_crc_error_leaves_no_destination
    build_zip(@zip) do |out|
      put_file(out, 'good.txt', 'good content', stored: true)
      put_file(out, 'bad.txt', 'bad content', stored: true)
    end
    corrupt_entry_data!(@zip, 'bad.txt')

    error = assert_raises(Zip::CRCError) do
      Zip::File.transactional_extract(@zip, @dest)
    end
    assert_match(/bad\.txt/, error.message)
    refute File.exist?(@dest)
    assert_empty leftover_staging
  end

  def test_file_operation_failure_leaves_no_partial_installation
    build_zip(@zip) do |out|
      put_file(out, 'first.txt', 'first')
      put_file(out, 'second.txt', 'second')
    end

    Zip::File.open(@zip) do |zf|
      entry = zf.get_entry('second.txt')
      entry.stub(:extract, ->(*) { raise IOError, 'simulated disk failure' }) do
        error = assert_raises(IOError) do
          zf.transactional_extract(@dest)
        end
        assert_equal 'simulated disk failure', error.message
      end
    end

    refute File.exist?(@dest)
    assert_empty leftover_staging
  end

  def test_staging_failure_leaves_the_existing_destination_untouched
    build_zip(@zip) do |out|
      put_file(out, 'new.txt', 'new', stored: true)
      put_file(out, 'boom.txt', 'boom', stored: true)
    end
    corrupt_entry_data!(@zip, 'boom.txt')

    FileUtils.mkdir_p(@dest)
    original = File.join(@dest, 'keep.txt')
    File.write(original, 'original content')

    assert_raises(Zip::CRCError) do
      Zip::File.transactional_extract(@zip, @dest, on_exist: :backup)
    end

    assert File.directory?(@dest)
    assert_equal 'original content', File.read(original)
    refute File.exist?(File.join(@dest, 'new.txt'))
    assert_empty leftover_backups
    assert_empty leftover_staging
  end

  def test_publish_failure_restores_the_existing_destination
    build_zip(@zip) do |out|
      put_file(out, 'new.txt', 'new')
    end
    FileUtils.mkdir_p(@dest)
    File.write(File.join(@dest, 'old.txt'), 'old content')

    original_rename = File.method(:rename)
    fake_rename = lambda do |src, dst|
      raise IOError, 'publish exploded' if
        File.basename(src).start_with?('.rubyzip-staging-')

      original_rename.call(src, dst)
    end
    with_fake_rename(fake_rename) do
      assert_raises(IOError) do
        Zip::File.transactional_extract(@zip, @dest, on_exist: :backup)
      end
    end

    assert File.directory?(@dest)
    assert_equal 'old content', File.read(File.join(@dest, 'old.txt'))
    refute File.exist?(File.join(@dest, 'new.txt'))
  end

  def test_unrecoverable_rollback_raises_publish_error_and_keeps_backup
    build_zip(@zip) { |out| put_file(out, 'new.txt', 'new') }
    FileUtils.mkdir_p(@dest)
    File.write(File.join(@dest, 'old.txt'), 'old content')

    file_rename = File.method(:rename)
    fake_rename = lambda do |src, dst|
      if dst == @dest && src.start_with?(File.join(@tmp, '.rubyzip-staging-'))
        raise IOError, 'publish exploded'
      end
      if src.start_with?(File.join(@tmp, '.rubyzip-backup-')) && dst == @dest
        raise IOError, 'restore exploded'
      end
      file_rename.call(src, dst)
    end
    with_fake_rename(fake_rename) do
      assert_raises(Zip::PublishError) do
        Zip::File.transactional_extract(@zip, @dest, on_exist: :backup)
      end
    end

    assert_equal 1, leftover_backups.length
    assert File.exist?(File.join(leftover_backups.first, 'old.txt'))
  end

  private

  def with_fake_rename(fake_rename)
    mod = Module.new do
      define_method(:rename) { |src, dst| fake_rename.call(src, dst) }
    end
    File.singleton_class.prepend(mod)
    yield
  ensure
    mod.send(:remove_method, :rename)
  end

  def leftover_staging
    Dir.children(@tmp).select { |name| name.start_with?('.rubyzip-staging-') }
       .map { |name| File.join(@tmp, name) }
  end

  def leftover_backups
    Dir.children(@tmp).select { |name| name.start_with?('.rubyzip-backup-') }
       .map { |name| File.join(@tmp, name) }
  end

  def build_zip(path)
    Zip::OutputStream.open(path) { |out| yield out }
  end

  def put_file(out, name, content, stored: false)
    method = stored ? Zip::Entry::STORED : Zip::Entry::DEFLATED
    out.put_next_entry(name, '', Zip::ExtraField.new, method)
    out.write(content)
  end

  def put_dir(out, name)
    out.put_next_entry(name)
  end

  # Writes an entry bypassing Zip::Entry's name validation, so that the
  # archive can contain names that the writer itself refuses to create
  # (absolute paths, etc.).
  def put_raw_entry(out, name, content)
    entry = Zip::Entry.new(@zip, name.delete_prefix('/'))
    entry.name = name
    out.put_next_entry(entry)
    out.write(content)
  end

  def put_symlink(out, name, target)
    entry = Zip::Entry.new(@zip, name)
    entry.fstype = Zip::FSTYPE_UNIX
    entry.instance_variable_set(:@ftype, :symlink)
    entry.external_file_attributes = (Zip::FILE_TYPE_SYMLINK << 28) | 0o777
    out.put_next_entry(entry)
    out.write(target)
  end

  # Flips a byte of the local-header data payload of a STORED entry, so it
  # no longer matches the entry recorded CRC. The entry name starts 30 bytes
  # after the 4-byte local header signature.
  def corrupt_entry_data!(path, entry_name)
    data = File.binread(path).b
    name_bytes = entry_name.b
    signature = [0x50, 0x4b, 0x03, 0x04].pack('C4')
    search = 0
    data_offset = loop do
      signature_offset = data.index(signature, search)
      flunk "entry #{entry_name} not found in archive" if signature_offset.nil?

      name_offset = signature_offset + 30
      name_length = data[signature_offset + 26, 2].unpack1('v')
      extra_length = data[signature_offset + 28, 2].unpack1('v')
      if data[name_offset, name_length] == name_bytes
        break name_offset + name_bytes.bytesize + extra_length
      end

      search = name_offset + name_length
    end
    data.setbyte(data_offset, data.getbyte(data_offset) ^ 0xff)
    File.binwrite(path, data)
  end
end
