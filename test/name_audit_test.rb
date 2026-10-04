# frozen_string_literal: true

require_relative 'test_helper'

class NameAuditTest < Minitest::Test
  EFS_FLAG = 0b100000000000
  VALID_DOS_DATE = 33 # 1980-01-01, so no invalid-date warnings are triggered.

  def teardown
    ::Zip.reset!
  end

  # Builds a zip archive byte-by-byte, so that tests can feed rubyzip
  # inconsistent metadata that Zip::OutputStream would never write.
  # Each entry spec supports:
  #   name:          used for both headers unless overridden
  #   local_name:    name bytes in the local file header
  #   central_name:  name bytes in the central directory record
  #   gp_flags:      general purpose flags (both headers)
  #   local_extra:   extra field bytes in the local file header
  #   central_extra: extra field bytes in the central directory record
  #   data:          entry contents (stored, uncompressed)
  def build_zip(entry_specs)
    io = StringIO.new(+''.b)
    central_records = []
    entry_specs.each do |spec|
      data = spec.fetch(:data, '').b
      crc = Zlib.crc32(data)
      local_name = spec.fetch(:local_name, spec[:name]).b
      central_name = spec.fetch(:central_name, spec[:name]).b
      local_extra = spec.fetch(:local_extra, '').b
      central_extra = spec.fetch(:central_extra, '').b
      gp_flags = spec.fetch(:gp_flags, 0)
      offset = io.pos
      io << [0x04034b50, 20, gp_flags, 0, 0, VALID_DOS_DATE, crc,
             data.bytesize, data.bytesize, local_name.bytesize,
             local_extra.bytesize].pack('VvvvvvVVVvv')
      io << local_name << local_extra << data
      central_records << [crc, data.bytesize, gp_flags, offset, central_name, central_extra]
    end
    cdir_offset = io.pos
    central_records.each do |crc, size, gp_flags, offset, name, extra|
      io << [0x02014b50, 20, 20, gp_flags, 0, 0, VALID_DOS_DATE, crc, size, size,
             name.bytesize, extra.bytesize, 0, 0, 0, 0, offset].pack('VvvvvvvVVVvvvvvVV')
      io << name << extra
    end
    cdir_size = io.pos - cdir_offset
    io << [0x06054b50, 0, 0, central_records.size, central_records.size,
           cdir_size, cdir_offset, 0].pack('VvvvvVVv')
    io.string
  end

  def unicode_path_extra(utf8_name, name_crc32)
    content = [1, name_crc32].pack('CV') + utf8_name.b
    'up' + [content.bytesize].pack('v') + content
  end

  def read_entries(zip_data)
    entries = nil
    ::Zip::File.open_buffer(StringIO.new(zip_data)) do |zf|
      entries = zf.entries
      yield zf if block_given?
    end
    entries
  end

  def mismatched_name_zip
    build_zip([{ local_name: 'local.txt', central_name: 'central.txt', data: 'x' }])
  end

  def test_default_mode_is_off
    assert_equal :off, ::Zip.name_audit_mode
  end

  def test_invalid_mode_raises_argument_error
    assert_raises(ArgumentError) { ::Zip.name_audit_mode = :bogus }
    ::Zip.name_audit_mode = 'strict' # Strings are accepted.
    assert_equal :strict, ::Zip.name_audit_mode
  end

  def test_off_mode_reads_normally_without_collecting_audit
    entries = read_entries(mismatched_name_zip)
    assert_equal 'central.txt', entries.first.name
    assert_nil entries.first.name_audit
  end

  def test_lenient_mode_records_all_name_locations
    ::Zip.name_audit_mode = :lenient
    entries = read_entries(mismatched_name_zip)
    entry = entries.first

    # Lenient mode preserves the existing read behaviour: the central
    # directory name wins.
    assert_equal 'central.txt', entry.name

    audit = entry.name_audit
    refute_nil audit
    assert_equal 'local.txt'.b, audit[:local_header].raw_bytes
    assert_equal 'central.txt'.b, audit[:central_directory].raw_bytes
    assert_equal 'local.txt', audit[:local_header].decoded_name
    assert_equal 'central.txt', audit[:central_directory].decoded_name
    assert_nil audit[:local_header].declared_encoding
    assert_includes audit.issues.map(&:code), :name_mismatch
    refute audit.consistent?
  end

  def test_strict_mode_raises_on_local_central_mismatch
    ::Zip.name_audit_mode = :strict
    error = assert_raises(::Zip::EntryNameMismatchError) do
      read_entries(mismatched_name_zip)
    end
    assert_includes error.message, 'central.txt'
    assert_includes error.issues.map(&:code), :name_mismatch
  end

  def test_unicode_path_extra_field_with_valid_crc
    ::Zip.name_audit_mode = :lenient
    extra = unicode_path_extra("R\u00e9sum\u00e9.txt", Zlib.crc32('resume.txt'))
    zip_data = build_zip([{ name: 'resume.txt', local_extra: extra, central_extra: extra }])
    entries = read_entries(zip_data)
    entry = entries.first

    unicode_path = entry.extra[:unicode_path]
    refute_nil unicode_path
    assert_equal 1, unicode_path.version
    assert_equal "R\u00e9sum\u00e9.txt", unicode_path.decoded_name
    assert unicode_path.valid_utf8?
    assert unicode_path.crc_valid_for?('resume.txt')
    refute unicode_path.crc_valid_for?('other.txt')

    # The parsed field packs back to the exact bytes that were read.
    assert_equal extra, entry.extra.to_c_dir_bin

    audit = entry.name_audit
    assert_equal "R\u00e9sum\u00e9.txt", audit[:unicode_path_extra].decoded_name
    assert_equal 'UTF-8', audit[:unicode_path_extra].declared_encoding
    assert audit.consistent?
  end

  def test_unicode_path_extra_field_with_bad_crc
    extra = unicode_path_extra("R\u00e9sum\u00e9.txt", Zlib.crc32('something-else.txt'))
    zip_data = build_zip([{ name: 'resume.txt', central_extra: extra }])

    ::Zip.name_audit_mode = :lenient
    entries = read_entries(zip_data)
    codes = entries.first.name_audit.issues.map(&:code)
    assert_includes codes, :unicode_path_crc_mismatch
    refute entries.first.extra[:unicode_path].crc_valid_for?('resume.txt')

    ::Zip.name_audit_mode = :strict
    error = assert_raises(::Zip::EntryNameMismatchError) { read_entries(zip_data) }
    assert_includes error.issues.map(&:code), :unicode_path_crc_mismatch
  end

  def test_invalid_utf8_where_efs_declares_utf8
    zip_data = build_zip([{ name: "bad\xFF\xFE.txt".b, gp_flags: EFS_FLAG }])

    ::Zip.name_audit_mode = :lenient
    entries = read_entries(zip_data)
    audit = entries.first.name_audit
    assert_equal 'UTF-8', audit[:central_directory].declared_encoding
    assert_includes audit.issues.map(&:code), :invalid_utf8
    assert_includes audit.to_s, 'declared=UTF-8'

    ::Zip.name_audit_mode = :strict
    error = assert_raises(::Zip::EntryNameMismatchError) { read_entries(zip_data) }
    assert_includes error.issues.map(&:code), :invalid_utf8
  end

  def test_duplicate_names_after_normalisation
    zip_data = build_zip([
                           { name: 'a\\b.txt', data: 'one' },
                           { name: 'a/b.txt', data: 'two' }
                         ])

    ::Zip.name_audit_mode = :lenient
    ::Zip.allow_duplicate_entry_names = true
    entries = read_entries(zip_data)
    assert_equal 2, entries.size
    entries.each do |entry|
      assert_equal 'a/b.txt', entry.name
      assert_includes entry.name_audit.issues.map(&:code), :duplicate_name
    end

    ::Zip.name_audit_mode = :strict
    error = assert_raises(::Zip::EntryNameMismatchError) { read_entries(zip_data) }
    assert_includes error.issues.map(&:code), :duplicate_name
    assert_includes error.message, 'a/b.txt'
  end

  def test_input_stream_lenient_collects_local_records
    ::Zip.name_audit_mode = :lenient
    bad_crc_extra = unicode_path_extra('other.txt', Zlib.crc32('wrong.txt'))
    zip_data = build_zip([
                           {
                             local_name: "bad\xFF\xFE.txt".b,
                             central_name: "bad\xFF\xFE.txt".b,
                             gp_flags: EFS_FLAG,
                             local_extra: bad_crc_extra
                           }
                         ])
    entry = nil
    ::Zip::InputStream.open(StringIO.new(zip_data)) do |zis|
      entry = zis.get_next_entry
    end
    audit = entry.name_audit
    refute_nil audit[:local_header]
    assert_nil audit[:central_directory]
    assert_equal :local_header, audit[:unicode_path_extra].context
    codes = audit.issues.map(&:code)
    assert_includes codes, :invalid_utf8
    assert_includes codes, :unicode_path_crc_mismatch
  end

  def test_input_stream_strict_raises
    ::Zip.name_audit_mode = :strict
    zip_data = build_zip([{ name: "bad\xFF\xFE.txt".b, gp_flags: EFS_FLAG }])
    assert_raises(::Zip::EntryNameMismatchError) do
      ::Zip::InputStream.open(StringIO.new(zip_data)) { |zis| zis.get_next_entry }
    end
  end

  def test_valid_archive_passes_strict
    ::Zip.unicode_names = true
    buffer = ::Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry("R\u00e9sum\u00e9.txt")
      zos.write 'content'
    end

    ::Zip.force_entry_names_encoding = 'UTF-8'
    ::Zip.name_audit_mode = :strict
    buffer.rewind
    ::Zip::File.open_buffer(buffer) do |zf|
      entry = zf.entries.first
      assert_equal "R\u00e9sum\u00e9.txt", entry.name
      assert entry.name_audit.consistent?
      assert_equal 'UTF-8', entry.name_audit[:local_header].declared_encoding
    end

    buffer.rewind
    ::Zip::InputStream.open(buffer) do |zis|
      assert zis.get_next_entry.name_audit.consistent?
    end
  end

  def test_name_audit_report
    ::Zip.name_audit_mode = :lenient
    read_entries(mismatched_name_zip) do |zf|
      report = zf.name_audit_report
      assert_includes report, 'Entry "central.txt"'
      assert_includes report, 'local_header'
      assert_includes report, 'central_directory'
      assert_includes report, 'raw=6c6f63616c2e747874' # 'local.txt'
      assert_includes report, 'name_mismatch'
    end
  end

  def test_name_audit_report_when_auditing_is_off
    read_entries(mismatched_name_zip) do |zf|
      assert_includes zf.name_audit_report, '(name auditing is off)'
    end
  end
end
