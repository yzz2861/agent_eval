# frozen_string_literal: true

require_relative 'test_helper'
require 'digest'

class ZipRecoveryTest < Minitest::Test
  LOCAL_ENTRY_SIGNATURE = 0x04034b50
  DATA_DESCRIPTOR_SIGNATURE = 0x08074b50
  GENERATED_DIR = 'test/data/generated'

  DOS_TIME = 0x7c21
  DOS_DATE = 0x5855

  def teardown
    ::Zip.reset!
  end

  # --- Fixture builders ---------------------------------------------------
  # The fixtures are hand-crafted byte strings so that the exact layout
  # (flags, descriptors, garbage) is under the test's control.

  def raw_deflate(data)
    deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
    out = deflater.deflate(data) + deflater.finish
    deflater.close
    out
  end

  def local_header(name, method, flags: 0, crc: 0, csize: 0, size: 0, extra: +''.b)
    encoded = name.b
    [LOCAL_ENTRY_SIGNATURE, 20, flags, method, DOS_TIME, DOS_DATE,
     crc, csize, size, encoded.bytesize, extra.bytesize].pack('VvvvvvVVVvv') + encoded + extra
  end

  def deflate_entry(name, data, descriptor: :none)
    compressed = raw_deflate(data)
    crc = Zlib.crc32(data)
    case descriptor
    when :none
      local_header(name, 8, crc: crc, csize: compressed.bytesize, size: data.bytesize) + compressed
    when :signed
      local_header(name, 8, flags: 0x08) + compressed +
        [DATA_DESCRIPTOR_SIGNATURE, crc, compressed.bytesize, data.bytesize].pack('VVVV')
    when :unsigned
      local_header(name, 8, flags: 0x08) + compressed +
        [crc, compressed.bytesize, data.bytesize].pack('VVV')
    end
  end

  def store_entry(name, data, descriptor: :none, crc: Zlib.crc32(data))
    case descriptor
    when :none
      local_header(name, 0, crc: crc, csize: data.bytesize, size: data.bytesize) + data
    when :signed
      local_header(name, 0, flags: 0x08) + data +
        [DATA_DESCRIPTOR_SIGNATURE, crc, data.bytesize, data.bytesize].pack('VVVV')
    when :missing # bit 3 set, but no descriptor ever follows
      local_header(name, 0, flags: 0x08) + data
    end
  end

  def empty_entry(name)
    local_header(name, 0)
  end

  def write_fixture(name, bytes)
    FileUtils.mkdir_p(GENERATED_DIR)
    path = File.join(GENERATED_DIR, name)
    File.binwrite(path, bytes)
    path
  end

  def entry_named(report, name)
    report.entries.find { |entry| entry.name == name }
  end

  # --- Tests --------------------------------------------------------------

  def test_scan_verifies_entries_when_central_directory_is_missing
    deflated_data = 'Hello, recovery! ' * 50
    stored_data = 'plain stored bytes ' * 20
    path = write_fixture('recovery_basic.zip',
                         deflate_entry('deflated.txt', deflated_data) +
                         store_entry('stored.bin', stored_data) +
                         empty_entry('empty.txt') +
                         empty_entry('dir/'))

    assert_raises(::Zip::Error) { ::Zip::File.open(path) {} }

    report = ::Zip::Recovery.scan(path)
    assert_equal %w[deflated.txt stored.bin empty.txt dir/],
                 report.verified_entries.map(&:name)
    assert_empty report.indeterminate_entries
    assert_empty report.unrecoverable_entries

    deflated = entry_named(report, 'deflated.txt')
    assert_equal deflated_data.bytesize, deflated.size
    assert_equal Zlib.crc32(deflated_data), deflated.crc
    assert(deflated.evidence.any? { |line| line.include?('CRC32 match') })

    stored = entry_named(report, 'stored.bin')
    assert_equal stored_data.bytesize, stored.size
    assert(stored.evidence.any? { |line| line.include?('local header') })
  end

  def test_pk_signatures_inside_payload_are_not_mistaken_for_entries
    # A plausible-looking (but CRC-inconsistent) local header, plus bare
    # signature bytes, hidden inside a stored payload.
    fake_header = local_header('evil.txt', 0, crc: 0, csize: 4, size: 4) + 'XYZW'
    payload = 'real data ' + fake_header + "PK\x03\x04junk PK\x07\x08 PK\x05\x06"
    path = write_fixture('recovery_payload_sigs.zip',
                         store_entry('innocent.bin', payload) +
                         deflate_entry('friend.txt', 'genuine entry'))

    report = ::Zip::Recovery.scan(path)

    assert_equal %w[innocent.bin friend.txt], report.verified_entries.map(&:name)
    evil = entry_named(report, 'evil.txt')
    assert(evil, 'expected the fake header to be reported, not silently trusted')
    assert(evil.unrecoverable?)
    assert(evil.evidence.any? { |line| line.include?('CRC32 mismatch') })
    assert(report.rejected_candidates.positive?)
  end

  def test_deflated_entry_with_signed_data_descriptor
    data = 'streamed deflate data ' * 30
    path = write_fixture('recovery_deflate_dd.zip',
                         deflate_entry('streamed.txt', data, descriptor: :signed))

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'streamed.txt')

    assert(entry.verified?)
    assert_equal Zlib.crc32(data), entry.crc
    assert_equal data.bytesize, entry.size
    assert(entry.evidence.any? { |line| line.include?('data descriptor') })
    assert(entry.evidence.any? { |line| line.include?('ended cleanly') })
  end

  def test_deflated_entry_with_unsigned_data_descriptor
    data = 'descriptor without signature ' * 30
    path = write_fixture('recovery_deflate_dd_unsigned.zip',
                         deflate_entry('streamed.txt', data, descriptor: :unsigned))

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'streamed.txt')

    assert(entry.verified?)
    assert_equal Zlib.crc32(data), entry.crc
  end

  def test_stored_entry_recovered_via_data_descriptor_scan
    data = 'stored streaming data ' * 20
    path = write_fixture('recovery_store_dd.zip',
                         store_entry('stored-stream.bin', data, descriptor: :signed))

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'stored-stream.bin')

    assert(entry.verified?)
    assert_equal Zlib.crc32(data), entry.crc
    assert_equal data.bytesize, entry.size
    assert(entry.evidence.any? { |line| line.include?('data descriptor confirmed') })
  end

  def test_stored_entry_without_reliable_length_is_indeterminate_not_guessed
    data = 'no length information anywhere ' * 10
    path = write_fixture('recovery_store_no_length.zip',
                         store_entry('mystery.bin', data, descriptor: :missing) +
                         deflate_entry('next.txt', 'following entry'))

    report = ::Zip::Recovery.scan(path)
    mystery = entry_named(report, 'mystery.bin')

    assert(mystery.indeterminate?)
    refute(mystery.verified?)
    assert(mystery.evidence.any? { |line| line.include?('cannot be recovered safely') })
    # The scanner must not guess a success, and the following entry must
    # still be found on its own evidence.
    assert(entry_named(report, 'next.txt').verified?)
    assert_equal ['next.txt'], report.verified_entries.map(&:name)
  end

  def test_truncated_entry_is_unrecoverable
    data = 'this deflate stream will be cut off ' * 20
    compressed = raw_deflate(data)
    declared = compressed.bytesize + 100
    header = local_header('truncated.txt', 8,
                          crc: Zlib.crc32(data), csize: declared, size: data.bytesize)
    path = write_fixture('recovery_truncated.zip', header + compressed)

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'truncated.txt')

    assert(entry.unrecoverable?)
    assert(entry.evidence.any? { |line| line.include?('truncated') })
  end

  def test_crc_mismatch_is_unrecoverable
    data = 'data with a lying header'
    path = write_fixture('recovery_bad_crc.zip',
                         store_entry('liar.bin', data, crc: Zlib.crc32(data) ^ 0xFF))

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'liar.bin')

    assert(entry.unrecoverable?)
    assert(entry.evidence.any? { |line| line.include?('CRC32 mismatch') })
  end

  def test_encrypted_entry_is_unrecoverable
    data = 'not really encrypted, but flagged as such'
    header = local_header('secret.txt', 0, flags: 0x01,
                          crc: Zlib.crc32(data), csize: data.bytesize, size: data.bytesize)
    path = write_fixture('recovery_encrypted.zip', header + data)

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'secret.txt')

    assert(entry.unrecoverable?)
    assert(entry.evidence.any? { |line| line.include?('encrypted') })
  end

  def test_zip64_sizes_in_local_header_extra_field
    data = 'zip64 marked entry ' * 10
    extra = [0x0001, 16, data.bytesize, data.bytesize].pack('vvQ<Q<')
    header = local_header('zip64.bin', 0, crc: Zlib.crc32(data),
                          csize: 0xFFFFFFFF, size: 0xFFFFFFFF, extra: extra)
    path = write_fixture('recovery_zip64.zip', header + data)

    report = ::Zip::Recovery.scan(path)
    entry = entry_named(report, 'zip64.bin')

    assert(entry.verified?)
    assert_equal data.bytesize, entry.size
    assert_equal data.bytesize, entry.compressed_size
  end

  def test_export_writes_verified_entries_to_new_archive_and_preserves_source
    deflated_data = 'export me ' * 40
    stored_data = 'export me too ' * 40
    bytes = deflate_entry('deflated.txt', deflated_data) +
            store_entry('stored.bin', stored_data) +
            store_entry('mystery.bin', 'indeterminate data', descriptor: :missing)
    source = write_fixture('recovery_export_source.zip', bytes)
    destination = File.join(GENERATED_DIR, 'recovery_exported.zip')
    FileUtils.rm_f(destination)

    source_digest_before = Digest::SHA256.file(source).hexdigest
    report = ::Zip::Recovery.export(source, destination)
    assert_equal source_digest_before, Digest::SHA256.file(source).hexdigest

    assert_equal %w[deflated.txt stored.bin], report.verified_entries.map(&:name)
    expected_time = ::Zip::DOSTime.parse_binary_dos_format(DOS_DATE, DOS_TIME)
    ::Zip::File.open(destination) do |zip|
      assert_equal %w[deflated.txt stored.bin], zip.entries.map(&:name)
      assert_equal deflated_data, zip.read('deflated.txt')
      assert_equal stored_data, zip.read('stored.bin')
      assert_equal expected_time, zip.get_entry('deflated.txt').time
    end
  end

  def test_export_refuses_to_overwrite_existing_destination
    source = write_fixture('recovery_no_clobber.zip', store_entry('a.txt', 'data'))
    destination = write_fixture('recovery_existing.zip', 'precious')

    assert_raises(::Zip::Error) { ::Zip::Recovery.export(source, destination) }
    assert_equal 'precious', File.binread(destination)
  end

  def test_report_manifest_lists_status_and_evidence
    path = write_fixture('recovery_manifest.zip',
                         deflate_entry('good.txt', 'fine') +
                         store_entry('stuck.bin', 'unknown length', descriptor: :missing))

    report = ::Zip::Recovery.scan(path)
    manifest = report.to_s

    assert_includes manifest, '1 verified'
    assert_includes manifest, '1 indeterminate'
    assert_includes manifest, '[verified] "good.txt"'
    assert_includes manifest, '[indeterminate] "stuck.bin"'
    assert_includes manifest, 'CRC32 match'

    hash = report.to_h
    assert_equal ['good.txt'], hash[:verified]
    assert_equal ['stuck.bin'], hash[:indeterminate]
    assert_equal 2, hash[:entries].size
    assert_equal :verified, hash[:entries].first[:status]
    assert_kind_of Array, hash[:entries].first[:evidence]
  end
end
