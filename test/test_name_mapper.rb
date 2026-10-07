# frozen_string_literal: true

require "common"
require "tmpdir"
require "fileutils"

# Unit tests for the remote->local name mapping layer and its
# reverse-lookup manifest. These run entirely against injectable policies
# (no host file system semantics are assumed).
class NameMapperTest < Net::SFTP::TestCase
  Operations = Net::SFTP::Operations

  def test_reject_strategy_keeps_safe_utf8_names_verbatim
    mapper = Operations::NameMapper.new(:strategy => :reject, :manifest_name => false)
    pairs = mapper.map(["plain.txt", "résumé", "a-b_c~1"], false)

    assert_equal ["plain.txt", "résumé", "a-b_c~1"], pairs.map(&:last)
    assert_equal [Encoding::ASCII_8BIT], pairs.map { |raw, _| raw.encoding }.uniq
  end

  def test_reject_strategy_rejects_invalid_utf8_without_replacement
    mapper = Operations::NameMapper.new(:strategy => :reject, :manifest_name => false)
    invalid = "bad\xFF\xFEname".b

    error = assert_raises(Operations::InvalidNameError) { mapper.map([invalid], false) }
    assert_equal invalid, error.name
    refute_match(/\uFFFD/, error.message)
    assert_match(/FF/, error.message)
  end

  def test_reject_strategy_rejects_separators_control_chars_and_trailing_dots
    mapper = Operations::NameMapper.new(:strategy => :reject, :manifest_name => false)
    ["a/b", "a\\b", "x" + 0.chr + "y", "tab\t", "trailing.", "space ",
     "..", ".", "nel\xC2\x85".b].each do |name|
      assert_raises(Operations::InvalidNameError) do
        mapper.map([name], false)
      end
    end
  end

  def test_reject_strategy_rejects_platform_reserved_names
    mapper = Operations::NameMapper.new(:strategy => :reject, :manifest_name => false)
    %w[CON con LPT9 nul.txt AUX COM1].each do |name|
      assert_raises(Operations::InvalidNameError) { mapper.map([name], false) }
    end
    assert_silent_map(mapper, ["normal.log", "console", "CONtinue"])
  end

  def test_reserved_name_check_is_injectable
    custom = ->(name) { name == "forbidden" }
    mapper = Operations::NameMapper.new(
      :strategy => :reject, :reserved_names => custom, :manifest_name => false
    )
    assert_raises(Operations::InvalidNameError) { mapper.map(["forbidden"], false) }
    # Windows names are accepted when the policy is replaced.
    assert_silent_map(mapper, ["CON", "LPT9"])

    disabled = Operations::NameMapper.new(
      :strategy => :reject, :reserved_names => nil, :manifest_name => false
    )
    assert_silent_map(disabled, ["CON"])
  end

  def test_escape_strategy_round_trips_all_kinds_of_bytes
    mapper = Operations::NameMapper.new(:strategy => :escape, :manifest_name => false)
    originals = [
      "plain.txt",
      "a/b\\b".b,
      "%already".b,
      "bad\xFF".b,
      "\xC3\xA9".b,           # valid UTF-8 é
      "e\xCC\x81".b,          # NFD form
      "enddot.".b,
      "endspace ".b,
      "CON".b
    ]

    pairs = mapper.map(originals, false)
    pairs.each do |raw, mapped|
      assert_equal raw, Operations::NameMapper.unescape(mapped),
                   "#{mapped.inspect} must reverse to #{raw.inspect}"
    end

    mapped = pairs.to_h
    assert_equal "%25already", mapped["%already".b]
    assert_equal "bad%FF", mapped["bad\xFF".b]
    assert_equal "enddot%2E", mapped["enddot.".b]
    assert_equal "%43ON", mapped["CON".b]
    assert_equal "\u00E9", mapped["\xC3\xA9".b]
  end

  def test_escape_handles_non_printing_unicode_and_internal_punctuation
    mapper = Operations::NameMapper.new(:strategy => :escape, :manifest_name => false)
    pairs = mapper.map(
      ["nel\xC2\x85".b, "a.b c.txt", "\xC2\xA0".b, "end\xC2\xA0".b],
      false
    )
    raw_to_mapped = pairs.to_h

    # NEL (U+0085) and no-break space are non-printable control-ish code
    # points and must be encoded rather than left on disk.
    assert_equal "nel%C2%85", raw_to_mapped["nel\xC2\x85".b]
    assert_equal "%C2%A0", raw_to_mapped["\xC2\xA0".b]

    # Internal spaces/dots are preserved; the trailing no-break space is
    # encoded.
    assert_equal "a.b c.txt", raw_to_mapped["a.b c.txt"]
    assert_equal "end%C2%A0", raw_to_mapped["end\xC2\xA0".b]

    pairs.each do |raw, mapped|
      assert_equal raw, Operations::NameMapper.unescape(mapped)
    end
  end

  def test_escape_is_injective_for_distinct_invalid_byte_sequences
    mapper = Operations::NameMapper.new(:strategy => :escape, :manifest_name => false)
    pairs = mapper.map(["x\xFF".b, "x\xFE".b, "x\uFFFD".b, "x?".b], false)
    mapped = pairs.map(&:last)
    assert_equal mapped.length, mapped.uniq.length
  end

  def test_identity_equivalency_does_not_fold_case
    mapper = Operations::NameMapper.new(:manifest_name => false)
    pairs = mapper.map(["Foo", "foo", "FOO"], false)
    assert_equal ["Foo", "foo", "FOO"], pairs.map(&:last)
  end

  def test_case_folding_equivalency_detects_secondary_collision
    mapper = Operations::NameMapper.new(
      :strategy => :reject,
      :equivalency => Operations::NameMapper::CASE_FOLD,
      :manifest_name => false
    )
    error = assert_raises(Operations::NameCollisionError) do
      mapper.map(["Report.txt", "report.TXT"], false)
    end
    assert_equal "report.TXT", error.local_name
  end

  def test_unicode_normalization_equivalency_detects_collision
    nfc = "\xC3\xA9".b
    nfd = "e\xCC\x81".b
    mapper = Operations::NameMapper.new(
      :strategy => :escape,
      :equivalency => Operations::NameMapper::UNICODE_NFD,
      :manifest_name => false
    )
    assert_raises(Operations::NameCollisionError) { mapper.map([nfc, nfd], false) }
  end

  def test_case_fold_and_nfd_are_composable
    mapper = Operations::NameMapper.new(
      :equivalency => Operations::NameMapper::CASE_FOLD_NFD,
      :manifest_name => false
    )
    assert_raises(Operations::NameCollisionError) do
      mapper.map(["\xC3\x89".b, "e\xCC\x81".b], false) # É vs é
    end
  end

  def test_custom_equivalency_can_model_arbitrary_file_systems
    # Pretend a file system strips all digits: "a1" and "a2" collide.
    strip_digits = ->(name) { name.gsub(/[0-9]/, "") }
    mapper = Operations::NameMapper.new(
      :equivalency => strip_digits, :manifest_name => false
    )
    assert_raises(Operations::NameCollisionError) { mapper.map(["a1", "a2"], false) }
    assert_silent_map(mapper, ["a1", "b2"])
  end

  def test_escaped_outputs_are_checked_for_secondary_collisions
    # Even if an equivalence rule folds an escaped token onto a literal
    # name, the mapped-name key check catches it.
    fold_percent = ->(name) { name.gsub(/%[0-9A-Fa-f]{2}/, "X") }
    mapper = Operations::NameMapper.new(
      :strategy => :escape, :equivalency => fold_percent, :manifest_name => false
    )
    assert_raises(Operations::NameCollisionError) do
      mapper.map(["aX", "a\xFF".b], false)
    end
  end

  def test_manifest_name_is_checked_against_top_level_entries_only
    mapper = Operations::NameMapper.new(:manifest_name => ".manifest")
    assert_raises(Operations::NameCollisionError) do
      mapper.map([".manifest"], true)
    end
    # Same name is fine in a nested directory layer.
    mapper.map([".manifest"], false)
  end

  def test_manifest_name_must_itself_be_safe
    assert_raises(ArgumentError) do
      Operations::NameMapper.new(:manifest_name => "a/b")
    end
    assert_raises(ArgumentError) do
      Operations::NameMapper.new(:manifest_name => "CON")
    end
  end

  def test_unknown_strategy_and_bad_callables_are_rejected
    assert_raises(ArgumentError) { Operations::NameMapper.new(:strategy => :nope) }
    assert_raises(ArgumentError) { Operations::NameMapper.new(:equivalency => "downcase") }
    assert_raises(ArgumentError) { Operations::NameMapper.new(:reserved_names => /x/) }
  end

  def test_manifest_preserves_raw_bytes_and_supports_reverse_lookup
    Dir.mktmpdir do |dir|
      mapper = Operations::NameMapper.new(:strategy => :escape, :manifest_name => "names.map")
      manifest = Operations::NameManifest.new(mapper, dir)
      manifest.add("a%FF", "/remote/a\xFF".b, "a\xFF".b, :file)
      manifest.add("sub", "/remote/sub", "sub", :directory)
      path = manifest.write!

      assert_equal File.join(dir, "names.map"), path
      records = Operations::NameManifest.read(path)
      file_record = records.find { |record| record.kind == "f" }
      assert_equal "a\xFF".b, file_record.remote_name
      assert_equal "/remote/a\xFF".b, file_record.remote_path
      assert_equal Encoding::ASCII_8BIT, file_record.remote_name.encoding

      original = Operations::NameManifest.original_name(dir, "a%FF", "names.map")
      assert_equal "a\xFF".b, original
    end
  end

  private

    def assert_silent_map(mapper, names, top_level = false)
      mapper.map(names, top_level)
    end
end
