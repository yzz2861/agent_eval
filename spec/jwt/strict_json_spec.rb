# frozen_string_literal: true

RSpec.describe JWT::StrictJSON do
  describe '.parse' do
    it 'parses valid JSON values' do
      expect(described_class.parse('{"a":[1,2.5,true,false,null,"x"]}')).to eq('a' => [1, 2.5, true, false, nil, 'x'])
    end

    it 'accepts whitespace around tokens' do
      expect(described_class.parse("  {\n\"a\" : 1 } \t")).to eq('a' => 1)
    end

    it 'accepts escaped keys and values' do
      expect(described_class.parse('"a\\nb\\"c"')).to eq("a\nb\"c")
      expect(described_class.parse('"\u00e9\uD83D\uDE00"')).to eq("\u00e9\u{1F600}")
    end

    it 'accepts repeated string values' do
      expect(described_class.parse('{"a":["x","x"],"b":"x"}')).to eq('a' => %w[x x], 'b' => 'x')
    end

    it 'rejects top level duplicate members' do
      expect { described_class.parse('{"a":1,"a":2}') }
        .to raise_error(described_class::ParseError, /duplicate_member.*position 7/)
    end

    it 'rejects nested duplicate members' do
      expect { described_class.parse('{"a":{"b":1,"b":2}}') }
        .to raise_error(described_class::ParseError, /duplicate_member.*position 12/)
    end

    it 'rejects duplicates inside an object nested in an array' do
      expect { described_class.parse('[{"b":1,"b":2}]') }
        .to raise_error(described_class::ParseError, /duplicate_member/)
    end

    it 'treats escaped key spellings of the same key as duplicates' do
      expect { described_class.parse('{"\u0061":1,"a":2}') }
        .to raise_error(described_class::ParseError, /duplicate_member/)
    end

    it 'treats escaped solidus as equal to the raw character' do
      expect { described_class.parse('{"a/b":1,"a\/b":2}') }
        .to raise_error(described_class::ParseError, /duplicate_member/)
    end

    it 'collides when a raw unicode key is also given as an escape' do
      expect { described_class.parse('{"\u00e9":1,"\u00E9":2}') }
        .to raise_error(described_class::ParseError, /duplicate_member/)
    end

    it 'keeps distinct escaped keys distinct' do
      expect(described_class.parse('{"a\/b":1,"a\\nb":2}')).to eq('a/b' => 1, "a\nb" => 2)
    end

    it 'reports the position on the duplicate key' do
      error = described_class.parse('{"a":1,"a":2}') rescue $!
      expect(error.position).to eq(7)
    end

    it 'rejects invalid UTF-8' do
      bad = '{"a":"'.b << 0xFF << '"'.b
      expect { described_class.parse(bad) }
        .to raise_error(described_class::ParseError, /invalid_encoding.*position/)
    end

    it 'rejects overlong UTF-8 encodings' do
      expect { described_class.parse("\xC0\xAF".b) }
        .to raise_error(described_class::ParseError, /invalid_encoding/)
      expect { described_class.parse("\xE0\x80\x80".b) }
        .to raise_error(described_class::ParseError, /invalid_encoding/)
      expect { described_class.parse("\xF0\x80\x80\x80".b) }
        .to raise_error(described_class::ParseError, /invalid_encoding/)
    end

    it 'rejects UTF-16 surrogates encoded as raw UTF-8' do
      expect { described_class.parse("\xED\xA0\x80".b) }
        .to raise_error(described_class::ParseError, /invalid_encoding/)
    end

    it 'rejects codepoints above Unicode U+10FFFF' do
      expect { described_class.parse("\xF4\x90\x80\x80".b) }
        .to raise_error(described_class::ParseError, /invalid_encoding/)
    end

    it 'accepts the highest valid multibyte sequences' do
      expect(described_class.parse('"'.b << "\xE0\xA0\x80".b << '"'.b)).to eq("\u0800")
      expect(described_class.parse('"'.b << "\xF4\x8F\xBF\xBF".b << '"'.b)).to eq("\u{10FFFF}")
    end

    it 'rejects unescaped control characters in strings' do
      expect { described_class.parse("\"\n\"") }
        .to raise_error(described_class::ParseError, /unescaped_control_character/)
    end

    it 'rejects malformed unicode escapes' do
      expect { described_class.parse('"\uD800"') }
        .to raise_error(described_class::ParseError, /invalid_unicode_escape/)
      expect { described_class.parse('"\uDC00"') }
        .to raise_error(described_class::ParseError, /invalid_unicode_escape/)
      expect { described_class.parse('"\u12"') }
        .to raise_error(described_class::ParseError)
    end

    it 'rejects invalid escape characters' do
      expect { described_class.parse('"\x"') }
        .to raise_error(described_class::ParseError, /invalid_escape/)
    end

    it 'rejects malformed numbers' do
      %w[01 00 1. - 1e 1e+ -x].each do |input|
        expect { described_class.parse(input) }
          .to raise_error(described_class::ParseError), "expected #{input.inspect} to be rejected"
      end
    end

    it 'rejects trailing data' do
      expect { described_class.parse('{"a":1}x') }
        .to raise_error(described_class::ParseError, /unexpected_token.*position 7/)
    end

    it 'rejects empty and whitespace only input' do
      expect { described_class.parse('') }.to raise_error(described_class::ParseError, /unexpected_end.*position 0/)
      expect { described_class.parse('   ') }.to raise_error(described_class::ParseError)
    end

    it 'rejects non string input with a parse error instead of a low level error' do
      expect { described_class.parse(nil) }.to raise_error(described_class::ParseError, /unexpected_token at position 0/)
    end

    it 'rejects repeated commas and trailing commas' do
      expect { described_class.parse('{"a":1,}') }.to raise_error(described_class::ParseError)
      expect { described_class.parse('[1,,2]') }.to raise_error(described_class::ParseError)
      expect { described_class.parse('{,"a":1}') }.to raise_error(described_class::ParseError)
    end

    it 'rejects unknown literals' do
      expect { described_class.parse('tru') }.to raise_error(described_class::ParseError)
      expect { described_class.parse('nulll') }.to raise_error(described_class::ParseError)
    end

    context 'depth limit' do
      it 'accepts documents up to the limit' do
        document = '[' * 100 + '1' + ']' * 100
        expect(described_class.parse(document, max_depth: 100)).to be_an(Array)
      end

      it 'rejects documents deeper than the limit' do
        document = '[' * 101 + '1' + ']' * 101
        expect { described_class.parse(document, max_depth: 100) }
          .to raise_error(described_class::ParseError, /depth_exceeded/)
      end

      it 'counts objects and arrays against the same limit' do
        expect { described_class.parse('{"a":{"b":{"c":1}}}', max_depth: 2) }
          .to raise_error(described_class::ParseError, /depth_exceeded/)
      end
    end

    context 'member limit' do
      it 'counts object members' do
        expect { described_class.parse('{"a":1,"b":2,"c":3}', max_members: 2) }
          .to raise_error(described_class::ParseError, /member_limit_exceeded/)
      end

      it 'counts array elements' do
        expect { described_class.parse('[1,2,3,4,5]', max_members: 4) }
          .to raise_error(described_class::ParseError, /member_limit_exceeded/)
      end

      it 'counts members across nested containers' do
        expect { described_class.parse('{"a":[1,2,3]}', max_members: 3) }
          .to raise_error(described_class::ParseError, /member_limit_exceeded/)
      end
    end

    context 'number lexical length limit' do
      it 'accepts numbers up to the limit' do
        expect(described_class.parse('1234567890', max_number_length: 10)).to eq(1_234_567_890)
      end

      it 'rejects longer number lexemes including sign and exponent' do
        expect { described_class.parse('12345678901', max_number_length: 10) }
          .to raise_error(described_class::ParseError, /number_too_long/)
        expect { described_class.parse('-1.23e+100000', max_number_length: 10) }
          .to raise_error(described_class::ParseError, /number_too_long/)
      end
    end

    it 'never includes input fragments in error messages' do
      secret = 'super-secret-payload-value'
      begin
        described_class.parse("{\"a\":\"#{secret}\",\"a\":1}")
        raise 'expected parse failure'
      rescue described_class::ParseError => e
        expect(e.message).not_to include(secret)
        expect(e.message).to match(/\AInvalid JSON: [a-z_]+ at position \d+\z/)
      end
    end

    it 'is a JSON::ParserError' do
      expect(described_class::ParseError).to be < ::JSON::ParserError
    end
  end
end
