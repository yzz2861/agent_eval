# frozen_string_literal: true

require "net/ftp"
require "test/unit"

class ListParserTest < Test::Unit::TestCase
  FIXTURE_DIR = File.expand_path("../../fixtures", __FILE__)

  # Fixed reference instant so year-less Unix timestamps are interpreted
  # deterministically without any network or clock dependency.
  REFERENCE_TIME = Time.utc(2026, 10, 8, 12, 0, 0)
  SERVER_OFFSET = 0

  def fixture(name)
    File.read(File.join(FIXTURE_DIR, name))
  end

  def parse(input, dialect = nil, **options)
    options[:reference_time] ||= REFERENCE_TIME
    options[:timezone] = SERVER_OFFSET unless options.key?(:timezone)
    Net::FTP::ListParser.parse(input, dialect, **options)
  end

  def parse_unix(input, **options)
    parse(input, :unix, **options)
  end

  def parse_dos(input, **options)
    parse(input, :dos, **options)
  end

  def parse_vms(input, **options)
    parse(input, :vms, **options)
  end

  #----------------------------------------------------------------
  # Dialect selection and detection
  #----------------------------------------------------------------

  def test_explicit_dialect_is_respected
    result = parse_unix("-rw-r--r-- 1 a b 1 Oct 8 09:00 f")
    assert_equal(:unix, result.dialect)
    assert(result.success?)
  end

  def test_string_dialect_is_accepted
    result = parse("-rw-r--r-- 1 a b 1 Oct 8 09:00 f", "unix")
    assert_equal(:unix, result.dialect)
  end

  def test_unknown_dialect_raises
    assert_raise(Net::FTP::ListParser::DialectError) do
      parse("x", :plan9)
    end
  end

  def test_detect_unix_dialect
    text = fixture("list_unix.txt")
    assert_equal(:unix, Net::FTP::ListParser.detect_dialect(text))
    assert_equal(:unix, parse(text).dialect)
  end

  def test_detect_dos_dialect
    text = fixture("list_dos.txt")
    assert_equal(:dos, Net::FTP::ListParser.detect_dialect(text))
    assert_equal(:dos, parse(text).dialect)
  end

  def test_detect_vms_dialect
    text = fixture("list_vms.txt")
    assert_equal(:vms, Net::FTP::ListParser.detect_dialect(text))
    assert_equal(:vms, parse(text).dialect)
  end

  def test_detect_returns_nil_for_unrecognizable_sample
    assert_nil(Net::FTP::ListParser.detect_dialect("nothing useful\n"))
    result = parse("nothing useful")
    assert_nil(result.dialect)
    assert_equal(0, result.entries.length)
  end

  def test_detect_returns_nil_for_only_header_lines
    assert_nil(Net::FTP::ListParser.detect_dialect("total 10\n\n"))
  end

  def test_mixed_dialect_is_not_guessed
    text = "-rw-r--r-- 1 a b 1 Oct 8 09:00 unix.txt\n" \
           "10-08-26  09:00AM              1 dos.txt"
    assert_equal(:ambiguous,
                 Net::FTP::ListParser.detect_dialect(text))
    result = parse(text)
    assert_nil(result.dialect)
    assert_equal([], result.entries)
    assert_equal(2, result.diagnostics.length)
    assert(result.diagnostics.all? { |diagnostic|
      diagnostic.reason.include?("could not be determined")
    })
  end

  def test_foreign_lines_under_explicit_dialect_are_diagnostics
    result = parse_unix("-rw-r--r-- 1 a b 1 Oct 8 09:00 ok\n" \
                        "10-08-26  09:00AM  1 foreign")
    assert_equal(1, result.entries.length)
    assert_equal(1, result.diagnostics.length)
    assert_equal("10-08-26  09:00AM  1 foreign",
                 result.diagnostics.first.line)
    assert_equal(:unix, result.diagnostics.first.dialect)
    assert_equal(false, result.success?)
  end

  def test_array_input_is_accepted
    result = parse(["-rw-r--r-- 1 a b 1 Oct 8 09:00 a",
                    "drwxr-xr-x 1 a b 1 Oct 8 09:00 d"], :unix)
    assert_equal(2, result.entries.length)
  end

  def test_crlf_input_is_accepted
    result = parse("-rw-r--r-- 1 a b 1 Oct 8 09:00 a\r\n", :unix)
    assert(result.success?)
  end

  #----------------------------------------------------------------
  # Unix
  #----------------------------------------------------------------

  def test_unix_fixture_types_and_counts
    result = parse(fixture("list_unix.txt"))
    files = result.entries.select(&:file?)
    directories = result.entries.select(&:directory?)
    symlinks = result.entries.select(&:symlink?)
    others = result.entries.reject { |entry|
      entry.file? || entry.directory? || entry.symlink?
    }
    assert_equal(3, files.length)
    assert_equal(2, directories.length)
    assert_equal(1, symlinks.length)
    assert_equal(1, others.length)
    assert_equal(1, result.diagnostics.length)
  end

  def test_unix_file
    line = "-rw-r--r--  1 bill staff 12345 " \
           "Sep 30 23:59 report final.doc"
    entry = parse_unix(line).entries.first
    assert(entry.file?)
    assert_equal(false, entry.directory?)
    assert_equal("report final.doc", entry.name)
    assert_equal(12345, entry.size)
    assert_equal("bill", entry.owner)
    assert_equal("staff", entry.group)
    assert_equal(1, entry.nlink)
    assert_equal(0o644, entry.mode)
    assert_equal(Time.utc(2026, 9, 30, 23, 59), entry.mtime)
    assert_equal(:minute, entry.mtime_precision)
    assert_equal(:unix, entry.dialect)
    assert_nil(entry.link_target)
  end

  def test_unix_directory
    line = "drwxr-xr-x  5 bill staff 512 Oct  1 08:00 docs"
    entry = parse_unix(line).entries.first
    assert(entry.directory?)
    assert_equal("docs", entry.name)
    assert_equal(512, entry.size)
    assert_equal(0o755, entry.mode)
    assert_equal(5, entry.nlink)
  end

  def test_unix_symlink_keeps_spaces_and_arrow_text
    line = "lrwxr-xr-x 1 bill staff 11 Oct  3 14:00 " \
           "link to stuff -> target dir/arrow -> name"
    entry = parse_unix(line).entries.first
    assert(entry.symlink?)
    assert_equal("link to stuff", entry.name)
    assert_equal("target dir/arrow -> name", entry.link_target)
  end

  def test_unix_file_name_may_contain_arrow_text
    line = "-rw-r--r-- 1 bill staff 3 Oct 8 09:00 a -> b.txt"
    entry = parse_unix(line).entries.first
    assert(entry.file?)
    assert_equal("a -> b.txt", entry.name)
    assert_nil(entry.link_target)
  end

  def test_unix_file_with_explicit_year_has_day_precision
    line = "-rw-r--r-- 1 bill staff 2048 " \
           "Mar  1  2020 archive 2020.tar"
    entry = parse_unix(line).entries.first
    assert_equal(Time.utc(2020, 3, 1), entry.mtime)
    assert_equal(:day, entry.mtime_precision)
  end

  def test_unix_recent_file_uses_reference_year
    entry = parse_unix("-rw-r--r-- 1 a b 1 Sep 30 23:59 f").entries.first
    assert_equal(2026, entry.mtime.year)
  end

  def test_unix_dated_file_more_than_a_day_forward_uses_previous_year
    entry = parse_unix("-rw-r--r-- 1 a b 1 Nov 12 09:00 f").entries.first
    assert_equal(2025, entry.mtime.year)
  end

  def test_unix_timezone_offset_is_applied
    entry = parse_unix("-rw-r--r-- 1 a b 1 Oct  7 09:00 f",
                       timezone: 8 * 3600).entries.first
    assert_equal(8 * 3600, entry.mtime.utc_offset)
    assert_equal("2026-10-07 09:00:00 +0800", entry.mtime.to_s)
  end

  def test_unix_string_timezone_offset_is_applied
    entry = parse_unix("-rw-r--r-- 1 a b 1 Oct  7 09:00 f",
                       timezone: "+05:30").entries.first
    assert_equal(5 * 3600 + 1800, entry.mtime.utc_offset)
  end

  def test_unix_defaults_timezone_to_reference_time_offset
    reference = Time.new(2026, 10, 8, 12, 0, 0, -5 * 3600)
    entry = parse("-rw-r--r-- 1 a b 1 Oct  7 09:00 f", :unix,
                  reference_time: reference,
                  timezone: nil).entries.first
    assert_equal(-5 * 3600, entry.mtime.utc_offset)
  end

  def test_unix_iso_date_with_seconds
    entry = parse_unix("-rw-r--r-- 1 a b 90 2024-02-29 10:11:12 f",
                       ).entries.first
    assert_equal(Time.utc(2024, 2, 29, 10, 11, 12), entry.mtime)
    assert_equal(:second, entry.mtime_precision)
  end

  def test_unix_invalid_calendar_date_is_a_diagnostic
    result = parse_unix("-rw-r--r-- 1 a b 90 2026-02-29 10:11:12 f")
    assert_equal(0, result.entries.length)
    assert_equal(1, result.diagnostics.length)
  end

  def test_unix_special_mode_bits
    line = "-rwsr-xr-x 1 root staff 16384 Jan 15  2024 tool"
    entry = parse_unix(line).entries.first
    assert_equal(0o4755, entry.mode)
  end

  def test_unix_device_node_is_other
    line = "crw-rw-rw- 1 root wheel 0,   5 Jan  2  2023 dev/null"
    entry = parse_unix(line).entries.first
    assert_equal(:other, entry.type)
    assert_equal("dev/null", entry.name)
    assert_nil(entry.size)
  end

  def test_unix_total_line_is_ignored
    listing = "total 212\n-rw-r--r-- 1 a b 1 Oct 8 09:00 f"
    result = parse_unix(listing)
    assert(result.success?)
    assert_equal(1, result.entries.length)
  end

  def test_unix_extended_permission_indicator
    entry = parse_unix("-rw-r--r--@ 1 a b 1 Oct 8 09:00 f").entries.first
    assert(entry.file?)
    assert_equal(0o644, entry.mode)
  end

  def test_unix_unknown_line_is_diagnostic_with_original_text
    line = "some unrecognized junk line here"
    result = parse_unix(line)
    assert_equal(0, result.entries.length)
    diagnostic = result.diagnostics.first
    assert_equal(line, diagnostic.line)
    assert_equal(:unix, diagnostic.dialect)
    assert_not_empty(diagnostic.reason)
  end

  def test_unix_symlink_without_target_keeps_type
    entry = parse_unix("lrwxr-xr-x 1 a b 3 Oct 8 09:00 dangling link")
    assert_equal(:symlink, entry.entries.first.type)
    assert_nil(entry.entries.first.link_target)
    assert_equal("dangling link", entry.entries.first.name)
  end

  def test_unix_line_with_invalid_bytes_is_diagnostic_not_raise
    junk = "\tweird \xf0 line".b
    result = parse_unix(junk)
    assert_equal(0, result.entries.length)
    assert_equal(junk, result.diagnostics.first.line)
  end

  #----------------------------------------------------------------
  # DOS / Windows
  #----------------------------------------------------------------

  def test_dos_file
    line = "09/30/2026  11:59 PM       12,345 report final.doc"
    entry = parse_dos(line).entries.first
    assert(entry.file?)
    assert_equal("report final.doc", entry.name)
    assert_equal(12345, entry.size)
    assert_equal(Time.utc(2026, 9, 30, 23, 59), entry.mtime)
    assert_equal(:minute, entry.mtime_precision)
  end

  def test_dos_directory
    line = "10/01/2026  08:00 AM    <DIR>          My Folder"
    entry = parse_dos(line).entries.first
    assert(entry.directory?)
    assert_equal("My Folder", entry.name)
    assert_nil(entry.size)
    assert_equal(Time.utc(2026, 10, 1, 8, 0), entry.mtime)
  end

  def test_dos_junction_is_symlink_with_target
    line = "10/03/2026  02:00 PM    <JUNCTION>     " \
           "link to stuff [D:\\target dir\\arrow -> name]"
    entry = parse_dos(line).entries.first
    assert(entry.symlink?)
    assert_equal("link to stuff", entry.name)
    assert_equal("D:\\target dir\\arrow -> name", entry.link_target)
  end

  def test_dos_symlinkd
    entry = parse_dos("10/03/2026  02:00 PM    <SYMLINKD>     dlink")
    assert_equal(:symlink, entry.entries.first.type)
  end

  def test_dos_24_hour_time
    entry = parse_dos("10-01-26  14:30             10 f").entries.first
    assert_equal(Time.utc(2026, 10, 1, 14, 30), entry.mtime)
  end

  def test_dos_seconds_are_preserved
    entry = parse_dos("10-01-26  14:30:05         10 f").entries.first
    assert_equal(Time.utc(2026, 10, 1, 14, 30, 5), entry.mtime)
    assert_equal(:second, entry.mtime_precision)
  end

  def test_dos_midnight_and_noon
    midnight = parse_dos("10/01/2026  12:00 AM              1 m")
    assert_equal(Time.utc(2026, 10, 1, 0, 0),
                 midnight.entries.first.mtime)
    noon = parse_dos("10/01/2026  12:00 PM              1 n")
    assert_equal(Time.utc(2026, 10, 1, 12, 0),
                 noon.entries.first.mtime)
  end

  def test_dos_two_digit_year
    entry = parse_dos("03-01-00  12:00 AM            1 f").entries.first
    assert_equal(2000, entry.mtime.year)
  end

  def test_dos_invalid_tag_is_diagnostic
    result = parse_dos("10-01-2026  08:00 AM    <WEIRD>       x")
    assert_equal(0, result.entries.length)
    assert_equal(1, result.diagnostics.length)
  end

  def test_dos_header_and_footer_are_ignored
    listing = <<~LIST
       Volume in drive C is SYSTEM
       Directory of C:\\Users\\bill

      10/01/2026  08:00 AM    <DIR>          docs
                     1 File(s)         10 bytes
                     1 Dir(s)   1,000 bytes free
    LIST
    result = parse_dos(listing)
    assert(result.success?)
    assert_equal(1, result.entries.length)
  end

  def test_dos_fixture_has_expected_entries
    result = parse(fixture("list_dos.txt"))
    assert_equal(6, result.entries.length)
    assert_equal(2, result.entries.count(&:directory?))
    assert_equal(3, result.entries.count(&:file?))
    assert_equal(1, result.entries.count(&:symlink?))
    assert_equal(1, result.diagnostics.length)
  end

  #----------------------------------------------------------------
  # VMS
  #----------------------------------------------------------------

  def test_vms_single_line_file
    line = "README.TXT;1                   5/10          " \
           "8-OCT-2026 09:30:16"
    entry = parse_vms(line).entries.first
    assert(entry.file?)
    assert_equal("README.TXT", entry.name)
    assert_equal(1, entry.version)
    assert_equal("TXT", entry.extension)
    assert_equal(5, entry.blocks_used)
    assert_equal(10, entry.blocks_allocated)
    assert_equal(5 * 512, entry.size)
    assert_equal(Time.utc(2026, 10, 8, 9, 30, 16), entry.mtime)
    assert_equal(:second, entry.mtime_precision)
  end

  def test_vms_directory
    entry = parse_vms("BUDGET.DIR;1        1/2       1-OCT-2026 08:00")
    assert(entry.entries.first.directory?)
    assert_equal(1, entry.entries.first.version)
    assert_equal("DIR", entry.entries.first.extension)
  end

  def test_vms_multi_line_entry_is_one_model
    lines = "OLD ARCHIVE.LIS;1\n" \
            "                               4/8           " \
            "<15-AUG-2026 10:00:00.00>"
    result = parse_vms(lines)
    assert_equal(1, result.entries.length)
    entry = result.entries.first
    assert_equal("OLD ARCHIVE.LIS", entry.name)
    assert_equal(1, entry.version)
    assert_equal(4, entry.blocks_used)
    assert_equal(8, entry.blocks_allocated)
    assert_equal(Time.utc(2026, 8, 15, 10, 0, 0), entry.mtime)
    assert(entry.raw.include?("\n"),
           "raw must retain every physical line of the entry")
  end

  def test_vms_day_precision
    entry = parse_vms("NOTE.TXT;1  3  30-SEP-2026").entries.first
    assert_equal(Time.utc(2026, 9, 30), entry.mtime)
    assert_equal(:day, entry.mtime_precision)
    assert_equal(3, entry.blocks_used)
    assert_nil(entry.blocks_allocated)
  end

  def test_vms_name_with_internal_spaces
    entry = parse_vms("NOTES PS.PS;2  3/9 30-SEP-2026 22:00 [APPEND]")
    assert_equal("NOTES PS.PS", entry.entries.first.name)
    assert_equal(2, entry.entries.first.version)
  end

  def test_vms_missing_date_is_diagnostic
    result = parse_vms("BROKEN.TXT;1")
    assert_equal(0, result.entries.length)
    diagnostic = result.diagnostics.first
    assert_equal("BROKEN.TXT;1", diagnostic.line)
  end

  def test_vms_wildcard_version_is_not_a_complete_entry
    result = parse_vms("FOO.TXT;*  1  8-OCT-2026 09:30")
    assert_equal(0, result.entries.length)
    assert_equal(1, result.diagnostics.length)
    assert_include(result.diagnostics.first.line, "FOO.TXT;*")
  end

  def test_vms_full_month_name
    entry = parse_vms("X.TXT;1 1 8-October-2026").entries.first
    assert_equal(Time.utc(2026, 10, 8), entry.mtime)
    assert_equal(:day, entry.mtime_precision)
  end

  def test_vms_orphan_fragment_is_diagnostic
    line = "                               4/8  <15-AUG-2026 10:00>"
    result = parse_vms(line)
    assert_equal(0, result.entries.length)
    assert_equal(1, result.diagnostics.length)
  end

  def test_vms_header_and_totals_are_ignored
    listing = <<~LIST
Directory DISK$USER:[BILL]

README.TXT;1  1  8-OCT-2026 09:30
Total of 1 file, 1/2 blocks
Grand total of 1 directory, 1/2 blocks
    LIST
    result = parse_vms(listing)
    assert(result.success?)
    assert_equal(1, result.entries.length)
  end

  def test_vms_fixture_has_expected_entries
    result = parse(fixture("list_vms.txt"))
    assert_equal(5, result.entries.length)
    assert_equal(1, result.entries.count(&:directory?))
    assert_equal(4, result.entries.count(&:file?))
    assert_equal([1, 1, 2, 1, 3],
                 result.entries.map(&:version))
    assert_equal(1, result.diagnostics.length)
  end

  #----------------------------------------------------------------
  # Result object and diagnostics
  #----------------------------------------------------------------

  def test_result_is_enumerable_and_returns_entries
    listing = "-rw-r--r-- 1 a b 1 Oct 8 09:00 a\n" \
              "drwxr-xr-x 1 a b 1 Oct 8 09:00 d"
    result = parse_unix(listing)
    names = result.map(&:name)
    assert_equal(["a", "d"], names)
    assert_equal(2, result.to_a.length)
    assert(result.success?)
  end

  def test_raw_contains_original_unix_line
    line = "-rw-r--r--   1 bill staff  100 Oct  7 09:00 f"
    assert_equal(line, parse_unix(line).entries.first.raw)
  end

  def test_diagnostic_inspect_mentions_line_and_reason
    diagnostic =
      Net::FTP::ListParser::ListDiagnostic.new("bad", "nope")
    assert_include(diagnostic.inspect, "bad")
    assert_include(diagnostic.inspect, "nope")
  end

  def test_invalid_timezone_raises
    assert_raise(Net::FTP::ListParser::TimezoneError) do
      parse_unix("-rw-r--r-- 1 a b 1 Oct 8 09:00 f",
                 timezone: "No/Such_Zone")
    end
  end

  def test_empty_listing_is_success_without_entries
    result = parse("")
    assert(result.success?)
    assert_equal([], result.entries)
    assert_equal([], result.diagnostics)
  end

  def test_list_method_is_still_raw_text_only
    source = File.read(File.expand_path("../../../../lib/net/ftp.rb",
                                        __FILE__))
    list_method = source[/def list\(\*args.*?^    end/m]
    assert_not_include(list_method, "ListParser")
  end
end
