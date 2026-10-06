# frozen_string_literal: true
require_relative 'helper'

module Psych
  # Tests for the +:string_style+ dump option: callers state a preference
  # (+:literal+ or +:folded+) and Psych picks a block scalar representation
  # that preserves the string byte-for-byte, falling back from folded to
  # literal and finally to a double-quoted scalar when necessary.
  class TestStringStyle < TestCase
    # Dump +str+ as the value of a one-key mapping, then assert the string
    # bytes survive the round trip exactly.  Returns the YAML so callers
    # can assert on the emitted style.
    def assert_byte_roundtrip(str, **opts)
      yaml = Psych.dump({ "k" => str }, **opts)
      loaded = Psych.load(yaml)["k"]
      assert_equal str.b, loaded.b, "bytes changed by round trip:\n" + yaml
      yaml
    end

    # The scalar style character Psych emitted for the value of "k",
    # one of: ">", "|", or '"' for a double-quoted scalar.
    def emitted_style(yaml)
      case yaml
      when /^k: *>/
        ">"
      when /^k: *\|/
        "|"
      when /^k: *"/
        '"'
      else
        flunk "unexpected YAML: " + yaml
      end
    end

    def foldable_multiline
      "Header\n\n" +
        ("some long line of text that should be folded nicely " * 3).strip +
        "\n\n- item\n"
    end

    def test_invalid_string_style
      assert_raise(ArgumentError) { Psych.dump("x", string_style: :bogus) }
      assert_raise(ArgumentError) { Psych.dump("x", string_style: "folded") }
    end

    def test_folded_preference_emits_folded_block
      yaml = assert_byte_roundtrip foldable_multiline, string_style: :folded, line_width: 40
      assert_equal ">", emitted_style(yaml)
      # the long line was actually folded onto several lines
      assert_operator yaml.lines.length, :>, foldable_multiline.lines.length + 2
    end

    def test_folded_preference_without_line_width_still_folds
      yaml = assert_byte_roundtrip foldable_multiline, string_style: :folded
      assert_equal ">", emitted_style(yaml)
    end

    def test_literal_preference_emits_literal_block
      yaml = assert_byte_roundtrip foldable_multiline, string_style: :literal, line_width: 40
      assert_equal "|", emitted_style(yaml)
      # literal keeps the long line as-is
      assert_includes yaml, "some long line of text that should be folded nicely " +        "some long line of text that should be folded nicely"
    end

    def test_default_behavior_is_unchanged
      omit 'libfyaml formats block scalars differently' if libfyaml?
      assert_equal "|", emitted_style(Psych.dump({ "k" => foldable_multiline }))
      assert_equal ">", emitted_style(Psych.dump({ "k" => "long " * 19 + "long" }, line_width: 12))
    end

    # Inputs that cannot be folded visibly fall back from folded to
    # literal, and inputs no block scalar can represent fall back to a
    # double-quoted scalar.  Every input must round trip byte-for-byte.
    FALLBACK_CASES = {
      "plain lines"                => ["foo\nbar\n", ">"],
      "foldable long line"         => [("word " * 30).strip + "\nshort\n", ">"],
      "leading blank line"         => ["\nfoo\n", ">"],
      "consecutive blank lines"    => ["foo\n\n\nbar\n", ">"],
      "no trailing newline"        => ["foo\nbar", ">"],
      "many trailing newlines"     => ["foo\nbar\n\n\n", ">"],
      "only newlines"              => ["\n\n\n", ">"],
      "unfoldable long word"       => ["x" * 90 + "\nshort\n", ">"],
      # leading whitespace reads ambiguously when folded: use literal
      "indented line"              => ["foo\n  bar\n", "|"],
      "indented first line"        => ["  foo\nbar\n", "|"],
      "indented code block"        => ["def foo\n  bar\nend\n", "|"],
      # no block scalar can keep these visibly: use double-quoted
      "trailing space"             => ["foo \nbar\n", '"'],
      "trailing space at end"      => ["foo\nbar ", '"'],
      "whitespace-only line"       => ["foo\n   \nbar\n", '"'],
      "tab character"              => ["foo\tbar\nbaz\n", '"'],
      "carriage return"            => ["foo\r\nbar\n", '"'],
      "control character"          => ["foo\x01bar\n", '"'],
    }

    def test_folded_fallback_ladder
      FALLBACK_CASES.each do |name, pair|
        str, expected = pair
        yaml = assert_byte_roundtrip str, string_style: :folded, line_width: 40
        assert_equal expected, emitted_style(yaml),
          name + ": expected style " + expected.inspect + ":\n" + yaml
      end
    end

    def test_literal_fallback_ladder
      FALLBACK_CASES.each do |name, pair|
        str, folded_style = pair
        expected = %w[> |].include?(folded_style) ? "|" : '"'
        yaml = assert_byte_roundtrip str, string_style: :literal, line_width: 40
        assert_equal expected, emitted_style(yaml),
          name + ": expected style " + expected.inspect + ":\n" + yaml
      end
    end

    def test_chomping_and_blank_lines_preserved
      [
        "foo\nbar",           # no trailing newline
        "foo\nbar\n",        # single trailing newline
        "foo\nbar\n\n",     # extra trailing newlines
        "foo\n\n\nbar\n",  # consecutive blank lines
        "\nfoo\n",           # leading blank line
        "foo\n  bar\n",      # leading whitespace
        "foo \nbar\n",       # trailing whitespace
        "foo\n  \nbar\n",   # whitespace-only line
      ].each do |str|
        assert_byte_roundtrip str, string_style: :folded
        assert_byte_roundtrip str, string_style: :literal
      end
    end

    def test_suggested_width_is_not_a_hard_cut
      str = "x" * 90 + "\nshort\n"
      yaml = assert_byte_roundtrip str, string_style: :folded, line_width: 20
      assert_equal ">", emitted_style(yaml)
      # the long word cannot be folded safely, so the line is kept long
      assert_includes yaml, "x" * 90
    end

    def test_anchors_and_aliases
      shared = { "text" => foldable_multiline }
      yaml = Psych.dump([shared, shared], string_style: :folded, line_width: 40)
      assert_match(/&\d+/, yaml)
      assert_match(/\*\d+/, yaml)
      loaded = Psych.load(yaml, aliases: true)
      assert_equal foldable_multiline.b, loaded[0]["text"].b
      assert_equal foldable_multiline.b, loaded[1]["text"].b
      assert_same loaded[0], loaded[1]
    end

    def test_nested_indentation
      nested = {
        "outer" => [
          { "inner" => foldable_multiline },
          { "deep" => { "deeper" => "foo\n  bar\n" } },
        ],
      }
      [2, 4].each do |indent|
        yaml = Psych.dump(nested, string_style: :folded, line_width: 40, indentation: indent)
        loaded = Psych.load(yaml)
        assert_equal foldable_multiline.b, loaded["outer"][0]["inner"].b
        assert_equal "foo\n  bar\n".b, loaded["outer"][1]["deep"]["deeper"].b
      end
    end

    def test_safe_dump_honors_string_style
      yaml = Psych.safe_dump({ "k" => foldable_multiline }, string_style: :folded, line_width: 40)
      assert_equal ">", emitted_style(yaml)
      assert_equal foldable_multiline.b, Psych.load(yaml)["k"].b
    end
  end
end
