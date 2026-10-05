# frozen_string_literal: true

require_relative 'test_helper'

class ReproducibleTest < Minitest::Test
  TEST_DIR = ::File.join(__dir__, 'data', 'generated', 'reproducible')
  ZIP_A    = ::File.join(TEST_DIR, 'a.zip')
  ZIP_B    = ::File.join(TEST_DIR, 'b.zip')
  SRC_A    = ::File.join(TEST_DIR, 'src_a')
  SRC_B    = ::File.join(TEST_DIR, 'src_b')

  CONTENTS = {
    'alpha.txt'        => "alpha\n",
    'beta.txt'         => "beta\n",
    'subdir/gamma.txt' => "gamma\n"
  }.freeze

  ZIP_EPOCH = ::Zip::DOSTime.local(1980, 1, 1, 0, 0, 0).freeze

  def setup
    FileUtils.rm_rf(TEST_DIR)
    FileUtils.mkdir_p(TEST_DIR)
    @symlink_supported = symlink_supported?
  end

  def teardown
    FileUtils.rm_rf(TEST_DIR)
  end

  # The acceptance criterion: two archives built from identical content,
  # but with different file creation orders, different mtimes and
  # different umasks, must be byte-identical in reproducible mode.
  def test_byte_identical_archives_despite_order_time_and_umask
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    create_source_tree(SRC_B, creation_order: %w[subdir/gamma.txt beta.txt alpha.txt],
                              base_mtime: ::Time.utc(2024, 7, 8, 9, 10, 12), umask: 0o077)

    order_a, order_b = entry_orders
    build_zip(ZIP_A, SRC_A, order_a, reproducible: true)
    build_zip(ZIP_B, SRC_B, order_b, reproducible: true)

    assert ::File.binread(ZIP_A) == ::File.binread(ZIP_B),
           'expected reproducible archives to be byte-identical'
  end

  # Sanity check that the test above is meaningful: without reproducible
  # mode, the same two trees produce different archives.
  def test_archives_differ_without_reproducible
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    create_source_tree(SRC_B, creation_order: %w[subdir/gamma.txt beta.txt alpha.txt],
                              base_mtime: ::Time.utc(2024, 7, 8, 9, 10, 12), umask: 0o077)

    order_a, order_b = entry_orders
    build_zip(ZIP_A, SRC_A, order_a)
    build_zip(ZIP_B, SRC_B, order_b)

    refute ::File.binread(ZIP_A) == ::File.binread(ZIP_B)
  end

  def test_extracted_contents_match
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    create_source_tree(SRC_B, creation_order: %w[subdir/gamma.txt beta.txt alpha.txt],
                              base_mtime: ::Time.utc(2024, 7, 8, 9, 10, 12), umask: 0o077)

    order_a, order_b = entry_orders
    build_zip(ZIP_A, SRC_A, order_a, reproducible: true)
    build_zip(ZIP_B, SRC_B, order_b, reproducible: true)

    [ZIP_A, ZIP_B].each do |zip|
      ::Zip::File.open(zip) do |zf|
        assert_equal expected_sorted_names, zf.entries.map(&:name)
        CONTENTS.each { |name, content| assert_equal content, zf.read(name) }
        assert_equal 'alpha.txt', zf.read('link') if @symlink_supported
      end
    end

    dest_a = ::File.join(TEST_DIR, 'out_a')
    dest_b = ::File.join(TEST_DIR, 'out_b')
    assert_output('', /skipped symlink/) { ::Zip::File.extract_all(ZIP_A, dest_a) }
    assert_output('', /skipped symlink/) { ::Zip::File.extract_all(ZIP_B, dest_b) }
    CONTENTS.each do |name, content|
      assert_equal content, ::File.read(::File.join(dest_a, name))
      assert_equal content, ::File.read(::File.join(dest_b, name))
    end
  end

  def test_symlinks_remain_symlinks
    skip 'symlinks are not supported/permitted on this platform' unless @symlink_supported

    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    build_zip(ZIP_A, SRC_A, entry_orders.first, reproducible: true)

    ::Zip::File.open(ZIP_A) do |zf|
      entry = zf.get_entry('link')
      assert entry.symlink?, 'symlink entry must not become a regular file'
      refute entry.file?
      assert_equal ::Zip::FSTYPE_UNIX, entry.fstype
      assert_equal ::Zip::FILE_TYPE_SYMLINK, entry.external_file_attributes >> 28
      assert_equal 0o755, entry.unix_perms
      assert_equal 'alpha.txt', zf.read('link')
    end
  end

  def test_default_metadata_normalization
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o077)
    build_zip(ZIP_A, SRC_A, entry_orders.first, reproducible: true)

    ::Zip::File.open(ZIP_A) do |zf|
      assert_equal expected_sorted_names, zf.entries.map(&:name)
      zf.each do |entry|
        assert_equal ZIP_EPOCH.to_i, entry.time.to_i, "mtime not normalized for #{entry.name}"
        assert_equal ::Zip::FSTYPE_UNIX, entry.fstype
        assert_empty entry.extra
      end
      assert_equal 0o644, zf.get_entry('alpha.txt').unix_perms
      assert_equal 0o755, zf.get_entry('subdir/').unix_perms
    end
  end

  def test_explicit_options_preserve_selected_metadata
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 5, 6, 7, 8, 10), umask: 0o077)
    order = entry_orders.first
    build_zip(ZIP_A, SRC_A, order,
              reproducible: { time: false, file_permissions: false, sort_entries: false })

    ::Zip::File.open(ZIP_A) do |zf|
      expected = order.map { |name| name == 'subdir' ? 'subdir/' : name }
      assert_equal expected, zf.entries.map(&:name), 'insertion order should be preserved'

      alpha = zf.get_entry('alpha.txt')
      src_mtime = ::File.stat(::File.join(SRC_A, 'alpha.txt')).mtime
      assert_equal (src_mtime.to_i / 2) * 2, alpha.time.to_i,
                   'source file mtime should be preserved (to DOS 2-second resolution)'
      assert_equal 0o600, alpha.unix_perms, 'umask-derived permissions should be preserved'
    end
  end

  def test_custom_fixed_time
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    build_zip(ZIP_A, SRC_A, entry_orders.first, reproducible: { time: ::Time.utc(2001, 2, 3, 4, 5, 6) })

    ::Zip::File.open(ZIP_A) do |zf|
      zf.each do |entry|
        assert_equal ::Zip::DOSTime.local(2001, 2, 3, 4, 5, 6).to_i, entry.time.to_i
      end
    end
  end

  def test_source_date_epoch_time
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    with_env('SOURCE_DATE_EPOCH', '1234567890') do
      build_zip(ZIP_A, SRC_A, entry_orders.first, reproducible: { time: :source_date_epoch })
    end

    ::Zip::File.open(ZIP_A) do |zf|
      zf.each do |entry|
        assert_equal ::Zip::DOSTime.local(2009, 2, 13, 23, 31, 30).to_i, entry.time.to_i
      end
    end
  end

  def test_source_date_epoch_requires_env_var
    with_env('SOURCE_DATE_EPOCH', nil) do
      assert_raises(::Zip::Error) { ::Zip::Reproducible.new(time: :source_date_epoch) }
    end
  end

  def test_fstype_normalized_to_unix
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    entry = ::Zip::Entry.new(ZIP_A, 'fat.txt')
    entry.fstype = ::Zip::FSTYPE_FAT

    ::Zip::File.open(ZIP_A, create: true, reproducible: true) do |zf|
      zf.add(entry, ::File.join(SRC_A, 'alpha.txt'))
    end

    ::Zip::File.open(ZIP_A) do |zf|
      assert_equal ::Zip::FSTYPE_UNIX, zf.get_entry('fat.txt').fstype
    end
  end

  def test_fstype_preserved_when_configured
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    entry = ::Zip::Entry.new(ZIP_A, 'fat.txt')
    entry.fstype = ::Zip::FSTYPE_FAT

    ::Zip::File.open(ZIP_A, create: true, reproducible: { fstype: false }) do |zf|
      zf.add(entry, ::File.join(SRC_A, 'alpha.txt'))
    end

    ::Zip::File.open(ZIP_A) do |zf|
      assert_equal ::Zip::FSTYPE_FAT, zf.get_entry('fat.txt').fstype
    end
  end

  def test_nonessential_extra_fields_are_stripped
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o022)
    entry = ::Zip::Entry.new(ZIP_A, 'timed.txt')
    entry.time = ::Time.utc(2021, 3, 4, 5, 6, 8) # records a universaltime extra field
    assert entry.absolute_time?

    ::Zip::File.open(ZIP_A, create: true, reproducible: true) do |zf|
      zf.add(entry, ::File.join(SRC_A, 'alpha.txt'))
    end

    ::Zip::File.open(ZIP_A) do |zf|
      saved = zf.get_entry('timed.txt')
      refute saved.absolute_time?
      assert_empty saved.extra
      assert_equal ZIP_EPOCH.to_i, saved.time.to_i
    end
  end

  def test_entries_copied_from_existing_archive_are_normalized_on_commit
    create_source_tree(SRC_A, creation_order: %w[alpha.txt beta.txt subdir/gamma.txt],
                              base_mtime: ::Time.utc(2020, 1, 2, 3, 4, 6), umask: 0o077)
    timed = ::Zip::Entry.new(ZIP_A, 'alpha.txt')
    timed.time = ::Time.utc(2021, 3, 4, 5, 6, 8) # records a universaltime extra field
    ::Zip::File.open(ZIP_A, create: true) do |zf|
      zf.add(timed, ::File.join(SRC_A, 'alpha.txt'))
    end

    # Committing in reproducible mode must normalize the pre-existing
    # entry (copied through raw) as well as newly added ones.
    ::Zip::File.open(ZIP_A, reproducible: true) do |zf|
      zf.add('beta.txt', ::File.join(SRC_A, 'beta.txt'))
    end

    ::Zip::File.open(ZIP_A) do |zf|
      assert_equal %w[alpha.txt beta.txt], zf.entries.map(&:name)
      zf.each do |entry|
        assert_equal ZIP_EPOCH.to_i, entry.time.to_i
        assert_equal 0o644, entry.unix_perms
        assert_empty entry.extra
      end
    end
  end

  def test_output_stream_normalizes_metadata_but_keeps_caller_order
    buffer = ::Zip::OutputStream.write_buffer(reproducible: true) do |zos|
      zos.put_next_entry('b.txt')
      zos << 'two'
      zos.put_next_entry('a.txt')
      zos << 'one'
    end

    zf = ::Zip::File.open_buffer(buffer)
    assert_equal %w[b.txt a.txt], zf.entries.map(&:name)
    entry = zf.get_entry('a.txt')
    assert_equal 0o644, entry.unix_perms
    assert_equal ::Zip::FSTYPE_UNIX, entry.fstype
    assert_equal ZIP_EPOCH.to_i, entry.time.to_i
    assert_empty entry.extra
  end

  def test_output_stream_bytes_are_deterministic
    build = lambda do
      ::Zip::OutputStream.write_buffer(reproducible: true) do |zos|
        zos.put_next_entry('a.txt')
        zos << 'content'
      end.string
    end

    assert build.call == build.call
  end

  def test_invalid_options_raise
    assert_raises(ArgumentError) { ::Zip::Reproducible.new(time: 'yesterday') }
    assert_raises(ArgumentError) { ::Zip::Reproducible.new(file_permissions: 0o10000) }
    assert_raises(ArgumentError) { ::Zip::Reproducible.new(fstype: 999) }
    assert_raises(ArgumentError) { ::Zip::Reproducible.resolve('yes') }
  end

  private

  def symlink_supported?
    ::File.symlink('probe_target', ::File.join(TEST_DIR, 'probe'))
    true
  rescue NotImplementedError, Errno::EACCES, Errno::EPERM
    false
  ensure
    ::FileUtils.rm_f(::File.join(TEST_DIR, 'probe'))
  end

  # Two different orderings of the same set of entries.
  def entry_orders
    base = %w[alpha.txt beta.txt subdir subdir/gamma.txt]
    base.insert(2, 'link') if @symlink_supported
    [base, base.reverse]
  end

  def expected_sorted_names
    names = %w[alpha.txt beta.txt subdir/ subdir/gamma.txt]
    names.insert(2, 'link') if @symlink_supported
    names
  end

  def create_source_tree(dir, creation_order:, base_mtime:, umask:)
    saved_umask = ::File.umask(umask)
    ::FileUtils.mkdir_p(::File.join(dir, 'subdir'))
    creation_order.each do |name|
      ::File.write(::File.join(dir, name), CONTENTS.fetch(name))
    end
    ::File.symlink('alpha.txt', ::File.join(dir, 'link')) if @symlink_supported
    creation_order.each_with_index do |name, i|
      ::File.utime(base_mtime + i, base_mtime + i, ::File.join(dir, name))
    end
    ::File.utime(base_mtime, base_mtime, ::File.join(dir, 'subdir'))
  ensure
    ::File.umask(saved_umask)
  end

  def build_zip(zip_path, src_dir, entry_order, **options)
    ::Zip::File.open(zip_path, create: true, **options) do |zf|
      entry_order.each { |name| zf.add(name, ::File.join(src_dir, name)) }
    end
  end

  def with_env(key, value)
    saved = ENV.fetch(key, nil)
    value.nil? ? ENV.delete(key) : ENV[key] = value
    yield
  ensure
    saved.nil? ? ENV.delete(key) : ENV[key] = saved
  end
end
