# frozen_string_literal: true

require 'fileutils'
require 'tmpdir'
require 'zlib'

require_relative 'test_helper'

class ZipFileExtractTransactionallyTest < Minitest::Test
  PATH_TRAVERSAL_ZIPS = 'test/data/path_traversal/jwilk'

  def setup
    @tmp = Dir.mktmpdir('rubyzip-transactional-test')
    @zip_path = File.join(@tmp, 'archive.zip')
    @destination = File.join(@tmp, 'installed')
  end

  def teardown
    FileUtils.remove_entry(@tmp) if File.directory?(@tmp)
    Zip.reset!
  end

  # -- basic behaviour ---------------------------------------------------

  def test_extracts_a_tree_and_returns_the_destination
    build_zip('top.txt' => 'top content',
              'sub/nested.txt' => 'nested',
              'empty/' => '')

    result = Zip::File.extract_transactionally(@zip_path, @destination)

    assert_equal @destination, result
    assert_equal 'top content', File.read(File.join(@destination, 'top.txt'))
    assert_equal 'nested', File.read(File.join(@destination, 'sub', 'nested.txt'))
    assert File.directory?(File.join(@destination, 'empty'))
  end

  def test_extracts_without_explicit_directory_entries
    build_zip('a/b/c/deep.txt' => 'deep content')

    Zip::File.extract_transactionally(@zip_path, @destination)

    assert_equal 'deep content',
                 File.read(File.join(@destination, 'a', 'b', 'c', 'deep.txt'))
  end

  def test_extracts_an_empty_archive_as_an_empty_directory
    build_zip({})

    Zip::File.extract_transactionally(@zip_path, @destination)

    assert File.directory?(@destination)
    assert_empty Dir.children(@destination)
  end

  def test_works_with_an_open_zip_file_instance
    build_zip('top.txt' => 'content')

    Zip::File.open(@zip_path) do |zip_file|
      zip_file.extract_transactionally(@destination)
    end

    assert_equal 'content', File.read(File.join(@destination, 'top.txt'))
  end

  def test_nothing_is_visible_until_the_whole_archive_has_been_extracted
    build_zip('top.txt' => 'content')

    refute File.exist?(@destination)
    Zip::File.extract_transactionally(@zip_path, @destination)
    assert_empty leftover_stage_directories
    assert File.directory?(@destination)
  end

  def test_preserves_file_permissions_from_the_archive
    source = File.join(@tmp, 'secret.txt')
    File.write(source, 'secret')
    File.chmod(0o600, source)
    FileUtils.rm_f(@zip_path)
    Zip::File.open(@zip_path, create: true) do |zip_file|
      zip_file.add('secret.txt', source)
    end

    Zip::File.extract_transactionally(@zip_path, @destination)

    assert_equal 0o600, File.stat(File.join(@destination, 'secret.txt')).mode & 0o7777
  end

  # -- existing destination handling -------------------------------------

  def test_refuses_an_existing_destination_by_default
    build_zip('top.txt' => 'new')
    FileUtils.mkdir_p(@destination)
    original_file = File.join(@destination, 'existing.txt')
    File.write(original_file, 'untouched')

    error = assert_raises(Zip::TransactionalExtractionError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end

    assert_kind_of Zip::TransactionalDestinationExistsError, error
    assert_equal 'untouched', File.read(original_file)
  end

  def test_refuses_an_existing_destination_explicitly
    build_zip('top.txt' => 'new')
    FileUtils.mkdir_p(@destination)
    File.write(File.join(@destination, 'old.txt'), 'old')

    assert_raises(Zip::TransactionalDestinationExistsError) do
      Zip::File.extract_transactionally(@zip_path, @destination,
                                        on_existing: :refuse)
    end

    assert File.exist?(File.join(@destination, 'old.txt'))
  end

  def test_refuses_a_pre_existing_broken_symlink_destination
    File.symlink(File.join(@tmp, 'nowhere'), @destination) rescue skip
    build_zip('top.txt' => 'new')

    assert_raises(Zip::TransactionalDestinationExistsError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end

    assert File.symlink?(@destination)
  end

  def test_replaces_an_existing_destination_with_a_backup
    build_zip('top.txt' => 'new content')
    FileUtils.mkdir_p(@destination)
    old_file = File.join(@destination, 'top.txt')
    File.write(old_file, 'old content')
    File.write(File.join(@destination, 'only_old.txt'), 'kept in backup')

    Zip::File.extract_transactionally(@zip_path, @destination,
                                      on_existing: :backup_replace)

    assert_equal 'new content', File.read(old_file)
    refute File.exist?(File.join(@destination, 'only_old.txt'))
    assert_empty Dir.glob(File.join(@tmp, '*.bak'))
  end

  def test_unknown_on_existing_strategy_raises_argument_error
    build_zip('top.txt' => 'content')

    assert_raises(ArgumentError) do
      Zip::File.extract_transactionally(@zip_path, @destination,
                                        on_existing: :nonsense)
    end

    refute File.exist?(@destination)
  end

  # -- preflight: duplicates, case folding, file/directory conflicts -----

  def test_rejects_duplicate_entry_paths
    build_zip_with_duplicate_names

    entries = loaded_entries

    error = assert_raises(Zip::DuplicateEntryPathError) do
      Zip::TransactionalExtractor.new(entries, @destination).extract
    end

    assert_equal 'a.txt', error.message[/path '([^']+)'/, 1]
    refute File.exist?(@destination)
  end

  def test_rejects_case_folded_conflicts_on_a_case_insensitive_filesystem
    build_zip('Foo.txt' => '1', 'foo.txt' => '2')

    assert_raises(Zip::CaseFoldingConflictError) do
      Zip::File.extract_transactionally(@zip_path, @destination,
                                        case_sensitive: false)
    end
    refute File.exist?(@destination)
  end

  def test_rejects_case_folded_conflicts_in_ancestor_directories
    build_zip('Sub/file.txt' => '1', 'sub/other.txt' => '2')

    assert_raises(Zip::CaseFoldingConflictError) do
      Zip::File.extract_transactionally(@zip_path, @destination,
                                        case_sensitive: false)
    end
  end

  def test_allows_case_differences_when_case_sensitive_is_forced
    build_zip('Foo.txt' => '1', 'foo.txt' => '2')

    # The preflight must not flag the names as a conflict when the caller
    # explicitly declares the destination to be case-sensitive.
    extractor = Zip::TransactionalExtractor.new(
      loaded_entries, @destination, case_sensitive: true
    )
    extractor.send(:preflight)
  end

  def test_rejects_a_file_and_directory_claiming_the_same_path
    build_zip_with_file_and_directory_same_name

    entries = loaded_entries

    assert_raises(Zip::EntryPathConflictError) do
      Zip::TransactionalExtractor.new(entries, @destination).extract
    end
    refute File.exist?(@destination)
  end

  def test_rejects_an_entry_under_a_path_claimed_by_a_file
    build_zip('a' => 'file', 'a/b' => 'child')

    assert_raises(Zip::EntryPathConflictError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
  end

  def test_rejects_an_entry_under_a_path_claimed_by_a_symlink
    build_zip('a' => { symlink: 'target' }, 'a/b' => 'child')

    assert_raises(Zip::EntryPathConflictError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
  end

  # -- preflight: unsafe paths -------------------------------------------

  def test_rejects_path_traversal_entries
    zip_file = File.join(PATH_TRAVERSAL_ZIPS, 'relative0.zip')

    assert_raises(Zip::UnsafeEntryPathError) do
      Zip::File.extract_transactionally(zip_file, @destination)
    end
    # The offending entry would have landed at the destination's parent,
    # i.e. inside the sandbox tmp directory - nothing should be there.
    refute File.exist?(File.join(File.dirname(@destination), 'moo'))
    refute File.exist?(@destination)
  end

  def test_rejects_embedded_path_traversal_entries
    zip_file = File.join(PATH_TRAVERSAL_ZIPS, 'relative2.zip')

    assert_raises(Zip::UnsafeEntryPathError) do
      Zip::File.extract_transactionally(zip_file, @destination)
    end
  end

  def test_rejects_absolute_entry_paths
    zip_file = File.join(PATH_TRAVERSAL_ZIPS, 'absolute1.zip')

    assert_raises(Zip::UnsafeEntryPathError) do
      Zip::File.extract_transactionally(zip_file, @destination)
    end
    refute File.exist?(@destination)
  end

  def test_rejects_entries_with_nul_bytes
    entries = [make_entry("good.txt"), make_entry("bad\0name.txt")]

    assert_raises(Zip::UnsafeEntryPathError) do
      Zip::TransactionalExtractor.new(entries, @destination).extract
    end
  end

  # -- preflight: symlinks -----------------------------------------------

  def test_rejects_an_absolute_symlink_target
    build_zip('link' => { symlink: '/etc/passwd' })

    error = assert_raises(Zip::UnsafeSymlinkError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end

    assert_includes error.message, '/etc/passwd'
    refute File.exist?(@destination)
  end

  def test_rejects_a_symlink_target_that_escapes_the_root
    build_zip('dir/link' => { symlink: '../../outside' })

    assert_raises(Zip::UnsafeSymlinkError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
  end

  def test_rejects_a_windows_style_absolute_symlink_target
    build_zip('link' => { symlink: 'C:\Windows\System32' })

    assert_raises(Zip::UnsafeSymlinkError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
  end

  def test_rejects_a_symlink_chain_that_escapes_the_root
    build_zip('a' => { symlink: 'b' },
              'b' => { symlink: '../outside' })

    assert_raises(Zip::UnsafeSymlinkError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
  end

  def test_rejects_the_fixture_directory_symlink_pointing_outside
    zip_file = File.join(PATH_TRAVERSAL_ZIPS, 'dirsymlink.zip')

    assert_raises(Zip::UnsafeSymlinkError) do
      Zip::File.extract_transactionally(zip_file, @destination)
    end
    # Nothing must be written outside the destination.
    refute File.exist?(File.join(@destination, 'moo'))
    refute File.exist?(@destination)
  end

  def test_extracts_a_symlink_that_points_inside_the_root
    build_zip('subdir/file.txt' => 'real content',
              'link' => { symlink: 'subdir/file.txt' })

    Zip::File.extract_transactionally(@zip_path, @destination)

    link = File.join(@destination, 'link')
    assert File.symlink?(link)
    assert_equal 'subdir/file.txt', File.readlink(link)
    assert_equal 'real content', File.read(link)
  end

  def test_does_not_extract_files_through_an_internal_directory_symlink
    build_zip('subdir/file.txt' => 'real',
              'link' => { symlink: 'subdir' },
              'link/file.txt' => 'through')

    assert_raises(Zip::EntryPathConflictError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
  end

  # -- verification ------------------------------------------------------

  def test_a_crc_error_leaves_no_partial_installation
    content = 'good data here'
    build_zip('f.txt' => content)
    corrupt_central_directory_crc!(@zip_path, content)

    assert_raises(Zip::CRCError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end

    refute File.exist?(@destination)
    assert_empty leftover_stage_directories
  end

  def test_a_corrupt_stored_entry_is_detected_and_rolled_back
    content = 'hello world'
    FileUtils.rm_f(@zip_path)
    Zip::File.open(@zip_path, create: true) do |zip_file|
      zip_file.get_output_stream('f.txt',
                                 compression_method: Zip::Entry::STORED) do |out|
        out.write content
      end
    end
    raw = File.binread(@zip_path)
    index = raw.index(content)
    raw[index, content.bytesize] = 'HELLO WORLD'
    File.binwrite(@zip_path, raw)

    assert_raises(Zip::CRCError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
    refute File.exist?(@destination)
  end

  def test_a_size_mismatch_is_detected
    content = 'good data'
    build_zip('f.txt' => content)
    raw = File.binread(@zip_path)
    packed = [content.bytesize].pack('V')
    index = raw.rindex(packed)
    raw[index, 4] = [content.bytesize + 9].pack('V')
    File.binwrite(@zip_path, raw)

    assert_raises(Zip::CRCError) do
      Zip::File.extract_transactionally(@zip_path, @destination)
    end
    refute File.exist?(@destination)
  end

  # -- filesystem failure injection --------------------------------------

  def test_an_extraction_io_failure_leaves_the_missing_destination_untouched
    build_zip('top.txt' => 'content', 'late.txt' => 'more')
    entries = loaded_entries
    late_entry = entries.find { |entry| entry.name == 'late.txt' }
    error = Class.new(StandardError)

    raised = assert_raises(error) do
      late_entry.stub(:get_input_stream, ->(*) { raise error, 'simulated IO failure' }) do
        Zip::TransactionalExtractor.new(entries, @destination).extract
      end
    end

    assert_equal 'simulated IO failure', raised.message
    refute File.exist?(@destination)
    assert_empty leftover_stage_directories
  end

  def test_an_extraction_io_failure_restores_an_existing_destination
    build_zip('top.txt' => 'new content')
    FileUtils.mkdir_p(@destination)
    File.write(File.join(@destination, 'important.txt'), 'must survive')
    entries = loaded_entries
    top_entry = entries.find { |entry| entry.name == 'top.txt' }
    error = Class.new(StandardError)

    assert_raises(error) do
      top_entry.stub(:get_input_stream, ->(*) { raise error, 'disk full' }) do
        Zip::TransactionalExtractor.new(
          entries, @destination, on_existing: :backup_replace
        ).extract
      end
    end

    assert File.directory?(@destination)
    assert_equal 'must survive',
                 File.read(File.join(@destination, 'important.txt'))
    assert_empty leftover_stage_directories
    assert_empty leftover_backups
  end

  def test_a_publish_failure_restores_the_original_destination
    build_zip('top.txt' => 'new content')
    FileUtils.mkdir_p(@destination)
    original = File.join(@destination, 'original.txt')
    File.write(original, 'original content')
    entries = loaded_entries

    calls = 0
    raised = assert_raises(RuntimeError) do
      with_rename_stub(->(source, target, delegate) {
        calls += 1
        # The second rename publishes the staged tree; fail that one.
        raise('simulated publish failure') if calls == 2

        delegate.call(source, target)
      }) do
        Zip::TransactionalExtractor.new(
          entries, @destination, on_existing: :backup_replace
        ).extract
      end
    end

    assert_equal 'simulated publish failure', raised.message
    assert File.directory?(@destination)
    assert_equal 'original content', File.read(original)
    assert_empty leftover_stage_directories
    assert_empty leftover_backups
  end

  def test_when_rollback_also_fails_a_rollback_error_is_raised_with_the_backup
    build_zip('top.txt' => 'new content')
    FileUtils.mkdir_p(@destination)
    original = File.join(@destination, 'original.txt')
    File.write(original, 'original content')
    entries = loaded_entries

    calls = 0
    raised = assert_raises(Zip::RollbackError) do
      with_rename_stub(->(source, target, delegate) {
        calls += 1
        # Call 2 is the publish rename, call 3 is the restore rename.
        raise('publish failure') if calls == 2
        raise('restore failure') if calls == 3

        delegate.call(source, target)
      }) do
        Zip::TransactionalExtractor.new(
          entries, @destination, on_existing: :backup_replace
        ).extract
      end
    end

    assert_includes raised.message, 'rollback failed'
    assert_includes raised.message, raised.backup_path
    assert File.exist?(raised.backup_path)
    assert_equal 'publish failure', raised.cause_error.message
  ensure
    FileUtils.rm_f(raised&.backup_path)
  end

  private

  # Builds a zip at @zip_path from a hash of name => content. A name ending
  # in '/' becomes a directory entry; a {symlink: 'target'} value becomes
  # a Unix symlink entry.
  def build_zip(entries = nil, path: @zip_path, **hash_entries)
    entries = entries || hash_entries
    entries = entries.to_a
    FileUtils.rm_f(path)
    Zip::OutputStream.open(path) do |out|
      entries.each do |name, value|
        if value.is_a?(Hash) && value.key?(:symlink)
          out.put_next_entry(symlink_entry(path, name))
          out.write(value[:symlink])
        else
          out.put_next_entry(name)
          out.write(value.to_s)
        end
      end
    end
    path
  end

  # Like #build_zip, but accepts an Array of [name, value] pairs so that
  # names which collide after normalisation (e.g. 'x' and 'x/') can both be
  # written. Caller is responsible for setting
  # Zip.allow_duplicate_entry_names as required.
  def build_zip_pairs(pairs = nil, path: @zip_path, **hash_entries)
    pairs = pairs || hash_entries
    FileUtils.rm_f(path)
    Zip::OutputStream.open(path) do |out|
      pairs.each do |name, value|
        if value.is_a?(Hash) && value.key?(:symlink)
          out.put_next_entry(symlink_entry(path, name))
          out.write(value[:symlink])
        else
          out.put_next_entry(name)
          out.write(value.to_s)
        end
      end
    end
    path
  end

  def build_zip_with_duplicate_names
    Zip.allow_duplicate_entry_names = true
    build_zip_pairs([['a.txt', 'first'], ['a.txt', 'second']])
  ensure
    Zip.allow_duplicate_entry_names = false
  end

  def build_zip_with_file_and_directory_same_name
    Zip.allow_duplicate_entry_names = true
    build_zip_pairs([['x', 'file-bytes'], ['x/', '']])
  ensure
    Zip.allow_duplicate_entry_names = false
  end

  # Loads every entry from the archive, honoring duplicate entry names if
  # the archive contains any.
  def loaded_entries(path: @zip_path)
    duplicates_were_allowed = Zip.allow_duplicate_entry_names
    Zip.allow_duplicate_entry_names = true
    entries = nil
    Zip::File.open(path) { |zip_file| entries = zip_file.entries.dup }
    entries
  ensure
    Zip.allow_duplicate_entry_names = duplicates_were_allowed
  end

  def symlink_entry(zip_path, name)
    entry = Zip::Entry.new(zip_path, name)
    entry.instance_variable_set(:@ftype, :symlink)
    entry
  end

  # Patches the CRC in the *central directory* (the last occurrence in the
  # file) so verification after extraction fails.
  def corrupt_central_directory_crc!(path, content)
    raw = File.binread(path)
    packed = [Zlib.crc32(content)].pack('V')
    index = raw.rindex(packed)
    refute_nil(index, 'expected to find the central directory CRC in the zip')
    raw[index, 4] = [Zlib.crc32(content) ^ 0x1234_5678].pack('V')
    File.binwrite(path, raw)
  end

  def make_entry(name, type: :file)
    entry = Zip::Entry.new('', name)
    entry.instance_variable_set(:@ftype, type)
    entry
  end

  # Temporarily replaces File.rename for the duration of the block. The
  # `on_rename` receives |source, target, delegate| for every rename; it
  # must call delegate.call(source, target) to perform the real rename.
  # The code under test runs in the trailing block while the stub is
  # installed. The native method is restored afterwards.
  def with_rename_stub(on_rename)
    original_rename = ::File.method(:rename)
    singleton = ::File.singleton_class
    singleton.send(:alias_method, :__rubyzip_rename_without_stub, :rename)
    handler = proc { |source, target| on_rename.call(source, target, original_rename) }
    singleton.send(:define_method, :rename, handler)
    yield
  ensure
    singleton.send(:remove_method, :rename)
    singleton.send(:alias_method, :rename, :__rubyzip_rename_without_stub)
    singleton.send(:remove_method, :__rubyzip_rename_without_stub)
  end

  def leftover_stage_directories
    Dir.children(File.dirname(@destination)).grep(/\.rubyzip-staging-/)
  end

  def leftover_backups
    Dir.children(File.dirname(@destination)).grep(/\.bak\z/)
  end
end
