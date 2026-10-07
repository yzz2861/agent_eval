# frozen_string_literal: true

require "net/ftp"
require "test/unit"

class ListParserTest < Test::Unit::TestCase
  NOW = Time.new(2026, 10, 8, 12, 0, 0, "+08:00")
  ZONE = "+08:00"

  UNIX_LINES = [
    "-rw-r--r--  1 alice  staff    1234 Oct  7 15:04 report final.txt",
    "drwxr-xr-x  2 alice  staff      64 Oct  8 09:30 sub dir",
    "lrwxrwxrwx  1 alice  staff      11 Oct  8  2024 link name -> target dir/file -> v2.txt",
    "-rw-r--r--  1 alice  staff       5 Dec 20 10:00 xmas.txt",
    "-rw-r--r--  1 alice  staff       6 Nov  1  2020 old.txt",
    "-rw-r--r--  1 alice  staff       7 Oct  8  2026 arrow -> in name.txt",
  ].freeze

  DOS_LINES = [
    "10-08-26  01:30PM    <DIR>          My Documents",
    "10-08-26  09:05AM             2048 report final.txt",
    "12-31-99  11:59PM                7 legacy.dat",
    "01-01-80  12:00AM                1 pivot.txt",
  ].freeze

  VMS_LINES = [
    "README.TXT;2            3/16        8-OCT-2026 12:34:56.78  (RWED,RWED,RE,)",
    "SUBDIR.DIR;1            1/16        7-OCT-2026 08:00:00     (RWE,RWE,RE,)",
    "A-VERY-LONG-FILE-NAME-THAT-WRAPS.DAT;7",
    "                       10/64       1-OCT-2026 00:00:01     (RWED,)",
  ].freeze

  def parse(lines, **opts)
    Net::FTP::ListParser.parse(lines, now: NOW, utc_offset: ZONE, **opts)
  end

  def entries(results)
    results.select(&:entry?)
  end

  def diagnostics(results)
    results.select(&:diagnostic?)
  end

  def test_unix_file_with_spaces
    entry = entries(parse([UNIX_LINES[0]], dialect: :unix)).first
    assert_equal("report final.txt", entry.pathname)
    assert_equal(:file, entry.type)
    assert(entry.file?)
    assert_false(entry.directory?)
    assert_false(entry.symlink?)
    assert_equal(1234, entry.size)
    assert_equal(Time.new(2026, 10, 7, 15, 4, 0, ZONE), entry.mtime)
    assert_equal(:minute, entry.mtime_precision)
    assert_nil(entry.link_target)
    assert_equal(UNIX_LINES[0], entry.raw)
  end

  def test_unix_directory
    entry = entries(parse([UNIX_LINES[1]], dialect: :unix)).first
    assert_equal("sub dir", entry.pathname)
    assert(entry.directory?)
    assert_equal(Time.new(2026, 10, 8, 9, 30, 0, ZONE), entry.mtime)
    assert_equal(:minute, entry.mtime_precision)
  end

  def test_unix_symlink_preserves_arrow_text
    entry = entries(parse([UNIX_LINES[2]], dialect: :unix)).first
    assert(entry.symlink?)
    assert_equal("link name", entry.pathname)
    assert_equal("target dir/file -> v2.txt", entry.link_target)
    assert_equal(:day, entry.mtime_precision)
    assert_equal(Time.new(2024, 10, 8, 0, 0, 0, ZONE), entry.mtime)
  end

  def test_unix_regular_file_keeps_arrow_text_in_name
    entry = entries(parse([UNIX_LINES[5]], dialect: :unix)).first
    assert(entry.file?)
    assert_equal("arrow -> in name.txt", entry.pathname)
    assert_nil(entry.link_target)
  end

  def test_unix_yearless_time_uses_reference_date
    entry = entries(parse([UNIX_LINES[3]], dialect: :unix)).first
    # Dec 20 10:00 would be in the future for the 2026-10-08 reference,
    # so it is interpreted as 2025.
    assert_equal(Time.new(2025, 12, 20, 10, 0, 0, ZONE), entry.mtime)
    assert_equal(:minute, entry.mtime_precision)
  end

  def test_unix_year_only_has_day_precision
    entry = entries(parse([UNIX_LINES[4]], dialect: :unix)).first
    assert_equal(Time.new(2020, 11, 1, 0, 0, 0, ZONE), entry.mtime)
    assert_equal(:day, entry.mtime_precision)
  end

  def test_unix_yearless_time_defaults_to_now_offset
    results = Net::FTP::ListParser.parse([UNIX_LINES[0]],
                                         dialect: :unix, now: NOW)
    entry = entries(results).first
    assert_equal(NOW.utc_offset, entry.mtime.utc_offset)
  end

  def test_dos_file_and_directory
    results = parse(DOS_LINES, dialect: :dos)
    assert_equal(4, entries(results).size)
    dir, file, legacy, pivot = entries(results)
    assert(dir.directory?)
    assert_equal("My Documents", dir.pathname)
    assert_nil(dir.size)
    assert_equal(Time.new(2026, 10, 8, 13, 30, 0, ZONE), dir.mtime)
    assert(file.file?)
    assert_equal("report final.txt", file.pathname)
    assert_equal(2048, file.size)
    assert_equal(Time.new(2026, 10, 8, 9, 5, 0, ZONE), file.mtime)
    assert_equal(:minute, file.mtime_precision)
    assert_equal(Time.new(1999, 12, 31, 23, 59, 0, ZONE), legacy.mtime)
    assert_equal(Time.new(1980, 1, 1, 0, 0, 0, ZONE), pivot.mtime)
  end

  def test_vms_file_version_and_precision
    entry = entries(parse([VMS_LINES[0]], dialect: :vms)).first
    assert(entry.file?)
    assert_equal("README.TXT", entry.pathname)
    assert_equal(2, entry.version)
    assert_equal(3, entry.size)
    assert_equal(Time.new(2026, 10, 8, 12, 34, 56 + Rational(78, 100), ZONE),
                 entry.mtime)
    assert_equal(:second, entry.mtime_precision)
  end

  def test_vms_directory
    entry = entries(parse([VMS_LINES[1]], dialect: :vms)).first
    assert(entry.directory?)
    assert_equal("SUBDIR", entry.pathname)
    assert_equal(1, entry.version)
  end

  def test_vms_multiline_entry
    results = parse(VMS_LINES, dialect: :vms)
    assert_equal(3, entries(results).size)
    assert_empty(diagnostics(results))
    wrapped = entries(results).last
    assert_equal("A-VERY-LONG-FILE-NAME-THAT-WRAPS.DAT", wrapped.pathname)
    assert_equal(7, wrapped.version)
    assert_equal(10, wrapped.size)
    assert_equal(VMS_LINES[2] + "\n" + VMS_LINES[3], wrapped.raw)
  end

  def test_vms_unterminated_continuation
    results = parse(["ORPHAN.TXT;1"], dialect: :vms)
    assert_empty(entries(results))
    diag = diagnostics(results).first
    assert_equal("ORPHAN.TXT;1", diag.raw)
    assert_equal(1, diag.line_number)
    assert_match(/continues on the next line/, diag.message)
  end

  def test_auto_detects_each_dialect
    assert_equal(6, entries(parse(UNIX_LINES)).size)
    assert_equal(4, entries(parse(DOS_LINES)).size)
    vms = parse(VMS_LINES)
    assert_equal(3, entries(vms).size)
    assert_empty(diagnostics(vms))
  end

  def test_auto_rejects_mixed_samples
    results = parse([UNIX_LINES[0], DOS_LINES[0]])
    assert_empty(entries(results))
    assert_equal(2, diagnostics(results).size)
    assert_equal(UNIX_LINES[0], diagnostics(results)[0].raw)
    assert_equal(DOS_LINES[0], diagnostics(results)[1].raw)
  end

  def test_unrecognized_lines_return_diagnostic_and_raw
    results = parse(["total 42", "not a listing line"], dialect: :unix)
    assert_empty(entries(results))
    assert_equal(2, diagnostics(results).size)
    diag = diagnostics(results).first
    assert_equal("total 42", diag.raw)
    assert_equal(1, diag.line_number)
    assert_match(/unix/, diag.message)
    assert(diag.diagnostic?)
    assert_false(diag.entry?)
  end

  def test_explicit_dialect_does_not_fall_back
    results = parse([DOS_LINES[0]], dialect: :unix)
    assert_empty(entries(results))
    assert_equal(DOS_LINES[0], diagnostics(results).first.raw)
  end

  def test_unknown_dialect_raises
    assert_raise(ArgumentError) do
      parse(UNIX_LINES, dialect: :zvm)
    end
  end

  def test_blank_lines_are_skipped
    results = parse(["", UNIX_LINES[0], "   "], dialect: :unix)
    assert_equal(1, results.size)
    assert_equal(UNIX_LINES[0], results.first.raw)
  end

  def test_accepts_a_single_string
    results = parse(UNIX_LINES.join("\r\n"))
    assert_equal(6, entries(results).size)
  end

  def test_list_still_returns_raw_strings
    assert_equal(Net::FTP.instance_method(:list),
                 Net::FTP.instance_method(:ls))
    assert_not_equal(Net::FTP::ListEntry, Net::FTP.instance_method(:list).owner)
  end
end
