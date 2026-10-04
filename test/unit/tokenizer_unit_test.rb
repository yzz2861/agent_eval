# frozen_string_literal: true

require 'test_helper'

class TokenizerTest < Minitest::Test
  def test_tokenize_strings
    assert_equal([' '], tokenize(' '))
    assert_equal(['hello world'], tokenize('hello world'))
    assert_equal(['{}'], tokenize('{}'))
  end

  def test_tokenize_variables
    assert_equal(['{{funk}}'], tokenize('{{funk}}'))
    assert_equal([' ', '{{funk}}', ' '], tokenize(' {{funk}} '))
    assert_equal([' ', '{{funk}}', ' ', '{{so}}', ' ', '{{brother}}', ' '], tokenize(' {{funk}} {{so}} {{brother}} '))
    assert_equal([' ', '{{  funk  }}', ' '], tokenize(' {{  funk  }} '))
  end

  def test_tokenize_blocks
    assert_equal(['{%comment%}'], tokenize('{%comment%}'))
    assert_equal([' ', '{%comment%}', ' '], tokenize(' {%comment%} '))

    assert_equal([' ', '{%comment%}', ' ', '{%endcomment%}', ' '], tokenize(' {%comment%} {%endcomment%} '))
    assert_equal(['  ', '{% comment %}', ' ', '{% endcomment %}', ' '], tokenize("  {% comment %} {% endcomment %} "))
  end

  def test_calculate_line_numbers_per_token_with_profiling
    assert_equal([1],       tokenize_line_numbers("{{funk}}"))
    assert_equal([1, 1, 1], tokenize_line_numbers(" {{funk}} "))
    assert_equal([1, 2, 2], tokenize_line_numbers("\n{{funk}}\n"))
    assert_equal([1, 1, 3], tokenize_line_numbers(" {{\n funk \n}} "))
  end

  def test_tokenize_with_nil_source_returns_empty_array
    assert_equal([], tokenize(nil))
  end

  def test_incomplete_curly_braces
    assert_equal(["{{.}", " "], tokenize('{{.} '))
    assert_equal(["{{}", "%}"], tokenize('{{}%}'))
    assert_equal(["{{}}", "}"], tokenize('{{}}}'))
  end

  def test_unmatching_start_and_end
    assert_equal(["{{%}"], tokenize('{{%}'))
    assert_equal(["{{%%%}}"], tokenize('{{%%%}}'))
    assert_equal(["{%", "}}"], tokenize('{%}}'))
    assert_equal(["{%%}", "}"], tokenize('{%%}}'))
  end

  def test_token_offsets
    tokenizer = new_tokenizer('a {{b}} {%c%} d', parse_context: Liquid::ParseContext.new(source_map: true))
    offsets   = []
    while tokenizer.send(:shift)
      offsets << [tokenizer.token_start, tokenizer.token_end]
    end

    assert_equal(
      [[0, 2], [2, 7], [7, 8], [8, 13], [13, 15]],
      offsets,
    )
  end

  def test_token_offsets_disabled_by_default
    tokenizer = new_tokenizer('a {{b}}')
    tokenizer.send(:shift)

    assert_nil(tokenizer.token_start)
    assert_nil(tokenizer.token_end)
  end

  def test_token_offsets_with_offset_base
    parse_context = Liquid::ParseContext.new(source_map: true)
    tokenizer     = parse_context.new_tokenizer("a\nb", for_liquid_tag: true, offset_base: 10)

    tokenizer.send(:shift)
    assert_equal(10, tokenizer.token_start)
    assert_equal(11, tokenizer.token_end)

    tokenizer.send(:shift)
    assert_equal(12, tokenizer.token_start)
    assert_equal(13, tokenizer.token_end)
  end

  private

  def new_tokenizer(source, parse_context: Liquid::ParseContext.new, start_line_number: nil)
    parse_context.new_tokenizer(source, start_line_number: start_line_number)
  end

  def tokenize(source)
    tokenizer = new_tokenizer(source)
    tokens    = []
    # shift is private in Liquid::C::Tokenizer, since it is only for unit testing
    while (t = tokenizer.send(:shift))
      tokens << t
    end
    tokens
  end

  def tokenize_line_numbers(source)
    tokenizer    = new_tokenizer(source, start_line_number: 1)
    line_numbers = []
    loop do
      line_number = tokenizer.line_number
      if tokenizer.send(:shift)
        line_numbers << line_number
      else
        break
      end
    end
    line_numbers
  end
end
