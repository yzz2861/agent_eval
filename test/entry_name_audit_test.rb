# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/name_audit_fixture_builder'

class EntryNameAuditTest < Minitest::Test
  FIXTURE_DIR = File.join(File.dirname(__FILE__), 'data', 'name_audit')

  def teardown
    ::Zip.reset!
  end

  def audit(builder)
    ::Zip::EntryNameAuditor.audit(::StringIO.new(NameAuditFixtureBuilder.send(builder)))
  end

  def fixture_path(name)
    File.join(FIXTURE_DIR, name)
  end

  # The fixtures on disk must match what the builder produces, so that the
  # handcrafted byte samples and the generator can never drift apart.
  def test_static_fixtures_match_builder
    NameAuditFixtureBuilder::SAMPLES.each do |filename, builder|
      assert_equal NameAuditFixtureBuilder.send(builder),
                   File.binread(fixture_path(filename)),
                   "Fixture #{filename} is stale; regenerate it with "                    'test/helpers/generate_name_audit_fixtures.rb'
    end
  end

  def test_report_lists_raw_bytes_encodings_and_decoded_names
    report = audit(:consistent_unicode_path)

    assert_predicate report, :ok?
    assert_equal 1, report.entries.size

    entry = report.entries.first
    assert_equal %i[central_directory local_header],
                 entry.observations.map(&:source)

    central = entry.central_observation
    assert_equal 'Résumé.txt'.b, central.raw
    assert_equal Encoding::UTF_8, central.declared_encoding
    assert_equal :efs_flag, central.encoding_source
    assert_equal 'Résumé.txt', central.decoded
    assert_predicate central, :valid_encoding?

    hash = central.to_h
    assert_equal 'Résumé.txt'.unpack1('H*'), hash[:raw_hex]
    assert_equal 'UTF-8', hash[:declared_encoding]
  end

  def test_unicode_path_crc_is_validated
    report = audit(:consistent_unicode_path)
    checks = report.entries.first.unicode_path_checks

    assert_equal 2, checks.size # one from the central directory, one local
    checks.each do |check|
      assert_equal 1, check.version
      assert_equal Zlib.crc32('Résumé.txt'.b), check.name_crc32
      assert_predicate check, :crc_ok?
      assert_equal 'Résumé.txt', check.unicode_name
    end
  end

  def test_local_central_name_mismatch_is_detected
    report = audit(:local_central_mismatch)

    refute_predicate report, :ok?
    assert_equal [:local_central_name_mismatch], report.issues.map(&:code)
    entry = report.entries.first
    assert_equal 'central-name.txt', entry.central_observation.decoded
    assert_equal 'local-name.txt', entry.local_observation.decoded
  end

  def test_unicode_path_crc_mismatch_is_detected
    report = audit(:unicode_path_crc_mismatch)

    refute_predicate report, :ok?
    assert_equal %i[unicode_path_crc_mismatch unicode_path_crc_mismatch],
                 report.issues.map(&:code)
    check = report.entries.first.unicode_path_checks.first
    assert_equal 0xDEADBEEF, check.name_crc32
    assert_equal Zlib.crc32('report.txt'), check.computed_crc32
  end

  def test_invalid_utf8_is_detected
    report = audit(:invalid_utf8_efs)

    refute_predicate report, :ok?
    assert_equal %i[invalid_utf8 invalid_utf8], report.issues.map(&:code)
    central = report.entries.first.central_observation
    assert_equal Encoding::UTF_8, central.declared_encoding
    refute_predicate central, :valid_encoding?
  end

  def test_normalized_name_collision_is_detected
    report = audit(:normalized_collision)

    refute_predicate report, :ok?
    assert_equal [:normalized_name_collision], report.issues.map(&:code)
    assert_equal 2, report.entries.size
    # The raw names differ (NFC vs NFD) but normalize to the same string.
    raws = report.entries.map { |entry| entry.central_observation.raw }
    assert_equal "café.txt".b, raws[0]
    assert_equal "café.txt".b, raws[1]
  end

  def test_unicode_path_alias_is_not_an_issue
    report = audit(:unicode_path_alias)

    assert_predicate report, :ok?
    entry = report.entries.first
    # Header name is the ASCII placeholder; the real name is in the field.
    assert_equal '____.txt', entry.central_observation.decoded
    assert_equal '日本語.txt', entry.unicode_path_checks.first.unicode_name
    assert_equal :zip_default, entry.central_observation.encoding_source
  end

  def test_strict_mode_raises_name_ambiguity_error
    report = audit(:local_central_mismatch)

    error = assert_raises(::Zip::NameAmbiguityError) { report.strict! }
    assert_kind_of ::Zip::Error, error
    assert_equal 1, error.issues.size
    assert_match(/local-name.txt/, error.message)
  end

  def test_strict_mode_passes_on_clean_archive
    report = audit(:consistent_unicode_path)

    assert_same report, report.strict!
  end

  def test_zip_file_lenient_mode_keeps_existing_read_behaviour
    zf = ::Zip::File.open(fixture_path('local_central_mismatch.zip'),
                          name_audit: :lenient)

    # The central directory name is used, exactly as without auditing.
    assert_equal ['central-name.txt'], zf.entries.map(&:name)
    refute_predicate zf.name_audit_report, :ok?
    assert_equal 'hello', zf.read('central-name.txt')
  ensure
    zf&.close
  end

  def test_zip_file_strict_mode_rejects_ambiguous_archive
    assert_raises(::Zip::NameAmbiguityError) do
      ::Zip::File.open(fixture_path('local_central_mismatch.zip'), name_audit: :strict)
    end
  end

  def test_zip_file_strict_mode_accepts_clean_archive
    zf = ::Zip::File.open(fixture_path('consistent_unicode_path.zip'), name_audit: :strict)

    assert_predicate zf.name_audit_report, :ok?
    assert_equal ['Résumé.txt'.b], zf.entries.map(&:name)
  ensure
    zf&.close
  end

  def test_zip_file_audit_is_off_by_default
    zf = ::Zip::File.open(fixture_path('local_central_mismatch.zip'))

    assert_nil zf.name_audit_report
    assert_equal ['central-name.txt'], zf.entries.map(&:name)
  ensure
    zf&.close
  end

  def test_zip_file_rejects_unknown_audit_mode
    error = assert_raises(::Zip::Error) do
      ::Zip::File.open(fixture_path('consistent_unicode_path.zip'), name_audit: :bogus)
    end
    assert_match(/Unknown name audit mode/, error.message)
  end

  def test_open_buffer_supports_name_audit
    data = File.binread(fixture_path('invalid_utf8_efs.zip'))

    assert_raises(::Zip::NameAmbiguityError) do
      ::Zip::File.open_buffer(data, name_audit: :strict) {}
    end

    report = nil
    ::Zip::File.open_buffer(data, name_audit: :lenient) do |zf|
      report = zf.name_audit_report
    end
    refute_predicate report, :ok?
  end

  def test_unicode_path_extra_field_is_parsed_and_preserved
    zf = ::Zip::File.open(fixture_path('consistent_unicode_path.zip'))
    field = zf.entries.first.extra[:unicodepath]

    assert_kind_of ::Zip::ExtraField::UnicodePath, field
    assert_equal 1, field.version
    assert_equal Zlib.crc32('Résumé.txt'.b), field.name_crc32
    assert_equal 'Résumé.txt'.b, field.unicode_name
    assert field.crc_matches?('Résumé.txt'.b)
    refute field.crc_matches?('other.txt')
    # The field round-trips byte-for-byte when the archive is rewritten.
    assert_equal field.to_local_bin, field.to_c_dir_bin
    assert_equal [0x7075].pack('v'), field.to_local_bin[0, 2]
  ensure
    zf&.close
  end

  def test_audit_restores_io_position
    io = ::StringIO.new(NameAuditFixtureBuilder.consistent_unicode_path)
    io.seek(7)

    ::Zip::EntryNameAuditor.audit(io)

    assert_equal 7, io.pos
  end

  def test_audit_handles_zip64_archives
    report = File.open(File.join(File.dirname(__FILE__), 'data', 'zip64-sample.zip'), 'rb') do |io|
      ::Zip::EntryNameAuditor.audit(io)
    end

    assert_predicate report, :ok?
    assert_equal 2, report.entries.size
  end
end
