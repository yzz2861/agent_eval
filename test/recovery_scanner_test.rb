# frozen_string_literal: true

require_relative 'test_helper'
require 'tmpdir'

class RecoveryScannerTest < Minitest::Test
  LOCAL_SIG = 0x04034b50
  DD_SIG = 0x08074b50

  def local_header(name:, method:, gp_flags: 0, crc: 0, csize: 0, usize: 0, version: 20)
    [LOCAL_SIG, version, gp_flags, method, 0, 0, crc, csize, usize,
     name.bytesize, 0].pack('VvvvvvVVVvv') + name.b
  end

  def stored_entry(name, content, **opts)
    local_header(name: name, method: 0, crc: Zlib.crc32(content),
                 csize: content.bytesize, usize: content.bytesize, **opts) + content
  end

  def raw_deflate(payload)
    deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
    deflater.deflate(payload, Zlib::FINISH)
  end

  def build_zip_bytes(entries)
    Zip::OutputStream.write_buffer do |zos|
      entries.each do |name, content, method|
        zos.put_next_entry(name, '', Zip::ExtraField.new, method)
        zos.write(content)
      end
    end.string
  end

  def truncate_central_directory(bytes)
    bytes[0...bytes.index("PK\x01\x02".b)]
  end

  def scan_data(data)
    Zip::RecoveryScanner.new(StringIO.new(data)).scan
  end

  def test_recovers_all_entries_when_central_directory_is_missing
    content_a = 'alpha content ' * 50
    content_b = "beta payload with an embedded PK\x03\x04 signature"
    bytes = build_zip_bytes([['alpha.txt', content_a, Zip::Entry::DEFLATED],
                             ['dir/beta.txt', content_b, Zip::Entry::STORED]])
    broken = truncate_central_directory(bytes)

    assert_raises(Zip::Error) { Zip::File.open_buffer(broken) {} }

    report = scan_data(broken)
    assert_equal 2, report.recovered.size
    assert_equal %w[alpha.txt dir/beta.txt], report.recovered.map(&:name)
    assert_equal content_a, report.recovered[0].data
    assert_equal content_b, report.recovered[1].data
    assert(report.recovered.all? { |e| e.evidence.any? { |line| line.include?('CRC32 verified') } })
  end

  def test_recovers_streamed_deflate_entry_with_signed_data_descriptor
    payload = 'streamed content ' * 20
    compressed = raw_deflate(payload)
    crc = Zlib.crc32(payload)
    data = local_header(name: 'streamed.txt', method: 8, gp_flags: 0x08) +
           compressed +
           [DD_SIG, crc, compressed.bytesize, payload.bytesize].pack('VVVV')

    report = scan_data(data)
    entry = report.recovered.first
    assert_equal 1, report.recovered.size
    assert_equal 'streamed.txt', entry.name
    assert_equal payload, entry.data
    assert_equal payload.bytesize, entry.size
    assert_equal compressed.bytesize, entry.compressed_size
    assert_equal crc, entry.crc
    assert(entry.evidence.any? { |line| line.include?('deflate stream ended cleanly') })
    assert(entry.evidence.any? { |line| line.include?('data descriptor') })
  end

  def test_recovers_streamed_deflate_entry_with_unsigned_data_descriptor
    payload = 'unsigned descriptor content'
    compressed = raw_deflate(payload)
    data = local_header(name: 'streamed.txt', method: 8, gp_flags: 0x08) +
           compressed +
           [Zlib.crc32(payload), compressed.bytesize, payload.bytesize].pack('VVV')

    report = scan_data(data)
    assert_equal 1, report.recovered.size
    assert_equal payload, report.recovered.first.data
  end

  def test_recovers_streamed_deflate_entry_without_any_descriptor
    payload = 'no descriptor here'
    data = local_header(name: 'streamed.txt', method: 8, gp_flags: 0x08) + raw_deflate(payload)

    report = scan_data(data)
    entry = report.recovered.first
    assert_equal 1, report.recovered.size
    assert_equal payload, entry.data
    assert(entry.evidence.any? { |line| line.include?('no data descriptor follows') })
  end

  def test_streamed_deflate_entry_followed_by_another_entry
    payload_one = 'first streamed'
    compressed_one = raw_deflate(payload_one)
    crc_one = Zlib.crc32(payload_one)
    data = local_header(name: 'one.txt', method: 8, gp_flags: 0x08) +
           compressed_one +
           [DD_SIG, crc_one, compressed_one.bytesize, payload_one.bytesize].pack('VVVV') +
           stored_entry('two.txt', 'second stored')

    report = scan_data(data)
    assert_equal %w[one.txt two.txt], report.recovered.map(&:name)
    assert_equal 'second stored', report.recovered[1].data
  end

  def test_streamed_stored_entry_is_reported_undetermined_not_guessed
    data = local_header(name: 'mystery.bin', method: 0, gp_flags: 0x08) +
           'payload of unknown length'

    report = scan_data(data)
    assert_equal 1, report.undetermined.size
    assert_empty report.recovered
    entry = report.undetermined.first
    assert_equal 'mystery.bin', entry.name
    assert(entry.evidence.any? { |line| line.include?('cannot be determined reliably') })
    assert(entry.evidence.any? { |line| line.include?('refusing to guess') })
  end

  def test_pk_signature_inside_payload_is_not_treated_as_an_entry
    fake_header = local_header(name: 'evil.txt', method: 0, crc: 0, csize: 3, usize: 3)
    real_payload = "prefix #{fake_header}abc suffix".b
    data = stored_entry('first.txt', real_payload) + stored_entry('second.txt', 'innocent')

    report = scan_data(data)
    assert_equal %w[first.txt second.txt], report.map(&:name)
    assert(report.all?(&:recovered?))
    assert_equal real_payload, report.recovered[0].data
  end

  def test_false_candidate_is_rejected_by_crc_when_rescanning
    fake_header = local_header(name: 'evil.txt', method: 0, crc: 0, csize: 3, usize: 3)
    good_payload = 'real content'
    # A header that declares the CRC of a payload we then corrupt.
    corrupt = local_header(name: 'corrupt.txt', method: 0,
                           crc: Zlib.crc32(good_payload),
                           csize: good_payload.bytesize,
                           usize: good_payload.bytesize) +
              "REAL #{fake_header}abc".b
    data = corrupt + stored_entry('second.txt', 'innocent')

    report = scan_data(data)
    assert_equal ['second.txt'], report.recovered.map(&:name)
    assert_equal 'corrupt.txt', report.unrecoverable.first.name
    assert(report.unrecoverable.first.evidence.any? { |line| line.include?('CRC32 mismatch') })
    refute(report.recovered.map(&:name).include?('evil.txt'))
  end

  def test_encrypted_entry_is_unrecoverable
    data = local_header(name: 'secret.txt', method: 0, gp_flags: 0x01,
                        crc: 123, csize: 10, usize: 10) + 'x' * 10

    report = scan_data(data)
    assert_equal 1, report.unrecoverable.size
    assert(report.unrecoverable.first.evidence.any? { |line| line.include?('encrypted') })
  end

  def test_entry_with_truncated_data_is_unrecoverable
    data = local_header(name: 'short.txt', method: 0, crc: 0, csize: 100, usize: 100) + 'tiny'

    report = scan_data(data)
    assert_equal 1, report.unrecoverable.size
    assert(report.unrecoverable.first.evidence.any? { |line| line.include?('truncated') })
  end

  def test_zip64_sizes_are_read_from_the_extra_field
    content = 'zip64 sized content'
    extra = [0x0001, 16, content.bytesize, content.bytesize].pack('vvQQ')
    header = [LOCAL_SIG, 45, 0, 0, 0, 0, Zlib.crc32(content), 0xFFFFFFFF, 0xFFFFFFFF,
              'zip64.txt'.bytesize, extra.bytesize].pack('VvvvvvVVVvv') + 'zip64.txt' + extra

    report = scan_data(header + content)
    assert_equal 1, report.recovered.size
    assert_equal content, report.recovered.first.data
    assert_equal content.bytesize, report.recovered.first.size
  end

  def test_recover_exports_files_and_manifest_without_touching_source
    entries = [['a.txt', 'alpha ' * 100, Zip::Entry::DEFLATED],
               ['dir/', '', Zip::Entry::STORED],
               ['dir/b.txt', "PK\x03\x04 embedded in stored payload", Zip::Entry::STORED]]
    bytes = truncate_central_directory(build_zip_bytes(entries))

    Dir.mktmpdir do |tmp|
      source = File.join(tmp, 'broken.zip')
      dest = File.join(tmp, 'rescued')
      File.binwrite(source, bytes)
      before = File.binread(source)

      report = Zip::RecoveryScanner.new(source).recover(dest)

      assert_equal before, File.binread(source), 'source archive must not be modified'
      assert_equal entries[0][1], File.binread(File.join(dest, 'a.txt'))
      assert_equal entries[2][1], File.binread(File.join(dest, 'dir/b.txt'))
      assert Dir.exist?(File.join(dest, 'dir'))

      manifest = File.read(File.join(dest, Zip::RecoveryScanner::MANIFEST_FILENAME))
      assert_includes manifest, 'RECOVERED'
      assert_includes manifest, 'CRC32 verified'
      assert_includes manifest, 'a.txt'
      assert_equal 3, report.recovered.size
    end
  end

  def test_recover_does_not_export_undetermined_or_traversal_entries
    stored = stored_entry('../evil.txt', 'escape attempt')
    streamed_store = local_header(name: 'mystery.bin', method: 0, gp_flags: 0x08) + 'unknown'
    data = stored + streamed_store

    Dir.mktmpdir do |tmp|
      source = File.join(tmp, 'broken.zip')
      dest = File.join(tmp, 'rescued')
      File.binwrite(source, data)

      report = Zip::RecoveryScanner.new(source).recover(dest)

      traversal = report.find { |entry| entry.name == '../evil.txt' }
      assert traversal.recovered?
      assert_nil traversal.exported_to
      assert(traversal.evidence.any? { |line| line.include?('not a safe relative path') })
      refute File.exist?(File.join(tmp, 'evil.txt'))
      refute File.exist?(File.join(dest, 'mystery.bin'))
      assert File.exist?(File.join(dest, Zip::RecoveryScanner::MANIFEST_FILENAME))
    end
  end

  def test_report_to_s_lists_status_and_evidence
    data = stored_entry('ok.txt', 'fine') +
           local_header(name: 'mystery.bin', method: 0, gp_flags: 0x08) + 'unknown'

    text = scan_data(data).to_s
    assert_includes text, 'RECOVERED'
    assert_includes text, 'UNDETERMINED'
    assert_includes text, 'ok.txt'
    assert_includes text, 'mystery.bin'
    assert_includes text, 'CRC32 verified'
  end
end
