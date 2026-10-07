require "common"
require "tmpdir"
require "fileutils"

class NameMapperTest < Net::SFTP::TestCase
  MAPPER = Net::SFTP::Operations::NameMapper
  ERROR = Net::SFTP::Operations::NameMappingError

  # Simulates a case-insensitive file system (e.g. Windows, default macOS).
  def case_insensitive
    @case_insensitive ||= ->(name) { name.downcase }
  end

  # Simulates a byte-oriented file system (e.g. Linux ext4).
  def byte_identity
    @byte_identity ||= ->(name) { name }
  end

  # Simulates a file system that compares names after NFD normalization.
  def nfd_normalizing
    @nfd_normalizing ||= ->(name) do
      utf8 = name.dup.force_encoding(Encoding::UTF_8)
      utf8.valid_encoding? ? utf8.unicode_normalize(:nfd) : name
    end
  end

  def mapper(options={})
    MAPPER.new(options)
  end

  def test_reject_maps_safe_names_to_themselves
    mapping = mapper(:strategy => :reject).map(%w(file1 file2.txt))
    assert_equal %w(file1 file2.txt), mapping.keys
    assert_equal %w(file1 file2.txt), mapping.values
  end

  def test_reject_detects_case_fold_collision_only_with_case_insensitive_equivalence
    names = %w(File.txt file.txt)

    # a byte-oriented file system (Linux ext4) keeps both
    mapping = mapper(:strategy => :reject, :equivalence => byte_identity).map(names)
    assert_equal names, mapping.values

    # a case-insensitive file system cannot
    assert_raises(ERROR) do
      mapper(:strategy => :reject, :equivalence => case_insensitive).map(names)
    end
  end

  def test_reject_detects_unicode_normalization_collision
    nfc = "caf\u00e9"
    nfd = "cafe\u0301"
    refute_equal nfc, nfd

    # default equivalence normalizes, so the collision is detected
    assert_raises(ERROR) { mapper(:strategy => :reject).map([nfc, nfd]) }

    # simulating an NFD-normalizing file system detects it too
    assert_raises(ERROR) do
      mapper(:strategy => :reject, :equivalence => nfd_normalizing).map([nfc, nfd])
    end

    # a byte-oriented file system keeps both
    mapping = mapper(:strategy => :reject, :equivalence => byte_identity).map([nfc, nfd])
    assert_equal [nfc.b, nfd.b].sort, mapping.values.sort
  end

  def test_invalid_utf8_names_keep_their_bytes_as_identity
    invalid = "a\xffb".b
    replacement = "a\ufffdb"

    mapping = mapper(:strategy => :reject).map([invalid, replacement])
    assert_equal invalid, mapping[invalid]
    assert_equal replacement.b, mapping[replacement.b]
    # the invalid name must not be silently replaced by U+FFFD
    refute_includes mapping[invalid].b, "\ufffd".b
  end

  def test_reject_rejects_separator_dot_segment_and_reserved_names
    m = mapper(:strategy => :reject)
    ["a/b", "a\\b", ".", "..", "CON", "con.txt", "aux", "LPT1", "a.", "a ", "a\tb", "a\x7fb"].each do |name|
      assert_raises(ERROR, "expected #{name.inspect} to be rejected") { m.map([name]) }
    end
  end

  def test_reject_raises_on_duplicate_remote_names
    assert_raises(ERROR) { mapper(:strategy => :reject).map(%w(same same)) }
  end

  def test_manifest_name_is_reserved_in_reject_mode
    assert_raises(ERROR) do
      mapper(:strategy => :reject).map(["file", MAPPER::DEFAULT_MANIFEST_NAME])
    end
  end

  def test_custom_manifest_name_is_reserved
    m = mapper(:strategy => :reject, :manifest => "MANIFEST.json", :equivalence => case_insensitive)
    assert_raises(ERROR) { m.map(["manifest.JSON"]) }
  end

  def test_manifest_can_be_disabled
    m = mapper(:strategy => :reject, :manifest => nil)
    mapping = m.map([MAPPER::DEFAULT_MANIFEST_NAME])
    assert_equal MAPPER::DEFAULT_MANIFEST_NAME, mapping.values.first
  end

  def test_invalid_strategy_manifest_name_and_equivalence_raise_argument_error
    assert_raises(ArgumentError) { mapper(:strategy => :bogus) }
    assert_raises(ArgumentError) { mapper(:manifest => "a/b") }
    assert_raises(ArgumentError) { mapper(:manifest => "..") }
    assert_raises(ArgumentError) { mapper(:equivalence => 42) }
  end

  def test_escape_escapes_invalid_utf8_reversibly_without_silently_replacing_bytes
    invalid = "a\xffb".b
    mapping = mapper(:strategy => :escape).map([invalid])
    assert_equal "a%FFb", mapping[invalid]
    assert_equal invalid, MAPPER.unescape(mapping[invalid])
  end

  def test_escape_is_reversible_for_every_byte_value
    all_bytes = (0..255).map { |byte| byte.chr.b }.join
    m = mapper(:strategy => :escape)
    assert_equal all_bytes, MAPPER.unescape(m.escape_unsafe(all_bytes))
    assert_equal all_bytes, MAPPER.unescape(m.escape_full(all_bytes))
  end

  def test_escape_resolves_case_fold_collision_by_fully_escaping
    mapping = mapper(:strategy => :escape, :equivalence => case_insensitive).map(%w(File.txt file.txt))
    assert_equal "File.txt", mapping["File.txt"]
    assert_equal "%66%69%6C%65%2E%74%78%74", mapping["file.txt"]
    assert_equal "file.txt", MAPPER.unescape(mapping["file.txt"])
  end

  def test_escape_escapes_percent_so_escaped_and_literal_namespaces_never_collide
    mapping = mapper(:strategy => :escape).map(["a b", "a%20b", "a%2520b"])
    assert_equal "a b", mapping["a b"]
    assert_equal "a%2520b", mapping["a%20b"]
    assert_equal "a%252520b", mapping["a%2520b"]
    assert_equal 3, mapping.values.uniq.length
    mapping.each { |remote, local| assert_equal remote, MAPPER.unescape(local) }
  end

  def test_escape_resolves_secondary_collision_introduced_by_escaping
    # both names escape minimally to candidates that differ only by case
    m = mapper(:strategy => :escape, :equivalence => case_insensitive)
    upper = "File\xff".b
    lower = "file\xff".b
    mapping = m.map([upper, lower])
    assert_equal "File%FF", mapping[upper]
    assert_equal "%66%69%6C%65%FF", mapping[lower]
    assert_equal lower, MAPPER.unescape(mapping[lower])
  end

  def test_escape_handles_reserved_and_platform_invalid_names
    m = mapper(:strategy => :escape)
    assert_equal "%43%4F%4E", m.map(["CON"])["CON"]
    assert_equal "a%2Fb", m.map(["a/b"])["a/b"]
    assert_equal "a%5Cb", m.map(["a\\b"])["a\\b"]
    assert_equal "%2E%2E", m.map([".."])[".."]
    assert_equal "%61%2E", m.map(["a."])["a."]
    assert_equal "%61%20", m.map(["a "])["a "]
    assert_equal "a%09b", m.map(["a\tb"])["a\tb"]
  end

  def test_escape_renames_remote_name_conflicting_with_manifest
    m = mapper(:strategy => :escape)
    mapping = m.map(["file", MAPPER::DEFAULT_MANIFEST_NAME])
    assert_equal "file", mapping["file"]
    escaped = mapping[MAPPER::DEFAULT_MANIFEST_NAME]
    refute_equal MAPPER::DEFAULT_MANIFEST_NAME, escaped
    assert_equal MAPPER::DEFAULT_MANIFEST_NAME, MAPPER.unescape(escaped)
    refute_includes mapping.values, MAPPER::DEFAULT_MANIFEST_NAME
  end

  def test_escape_raises_when_equivalence_makes_resolution_impossible
    hostile = ->(_name) { "same" }
    assert_raises(ERROR) do
      mapper(:strategy => :escape, :equivalence => hostile).map(%w(one two))
    end
  end

  def test_manifest_round_trip_recovers_original_remote_bytes
    invalid = "bad\xffname".b
    m = mapper(:strategy => :escape)
    mapping = m.map(["plain.txt", invalid, "a b"])
    recovered = MAPPER.parse_manifest(m.manifest_content(mapping))
    assert_equal mapping.length, recovered.length
    mapping.each do |remote, local|
      assert_equal remote, recovered[local.b], "expected manifest to map #{local.inspect} back to #{remote.inspect}"
    end
  end

  def test_write_manifest_writes_parseable_file
    m = mapper(:strategy => :escape)
    mapping = m.map(["a\xffb".b])
    dir = Dir.mktmpdir
    begin
      path = m.write_manifest(dir, mapping)
      assert_equal File.join(dir, MAPPER::DEFAULT_MANIFEST_NAME), path
      recovered = MAPPER.parse_manifest(File.read(path))
      assert_equal({ mapping.values.first.b => "a\xffb".b }, recovered)
    ensure
      FileUtils.remove_entry(dir)
    end
  end
end
