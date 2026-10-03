# frozen_string_literal: true

RSpec.describe JWT::StrictJSON do
  describe '.parse' do
    subject(:parse) { described_class.parse(json) }

    context 'with valid JSON' do
      {
        'empty object' => '{}',
        'empty array' => '[]',
        'object' => %q({"alg":"HS256","b64":false,"crit":["b64"]}),
        'nested' => %q({"a":{"b":[1,2,{"c":null}],"d":true}}),
        'whitespace' => "  {\n\t\"a\" : 1 } ",
        'integer' => '1234567890123456789',
        'fraction and exponent' => '1.5e3',
        'negative exponent' => '-0.25E-2',
        'literal values' => '[true,false,null]',
        'escapes' => %q("a\u0061\\\/\b\f\n\r\t"),
        'unicode escapes' => '"\u00e9\u00C9"',
        'surrogate pair' => '"\ud83d\ude00"',
        'utf8 string' => '"é"',
        'top level scalar' => '42',
        'same string values' => %q({"a":"same","b":"same","c":["same"]})
      }.each do |description, input|
        it "parses #{description}" do
          expect(described_class.parse(input)).to eq(::JSON.parse(input))
        end
      end

      it 'uses UTF-8 for decoded strings' do
        result = described_class.parse('"\u00e9"')
        expect(result.encoding).to eq(Encoding::UTF_8)
      end

      it 'accepts the maximum nesting depth' do
        json = '[' * max_depth + '1' + ']' * max_depth
        expect { described_class.parse(json) }.not_to raise_error
      end

      it 'accepts the maximum number of object members' do
        json = members_json(max_members)
        expect(described_class.parse(json).size).to eq(max_members)
      end

      it 'accepts a number with the maximum lexical length' do
        expect(described_class.parse('1' * max_number_length)).to eq(Integer('1' * max_number_length))
      end
    end

    context 'with duplicate members' do
      it 'rejects a top level duplicate key at the second key position' do
        json = %q({"a":1,"a":2})
        error = parse_error(json)
        expect(error.category).to eq(:duplicate_member)
        expect(error.position).to eq(json.index('"a"', 2))
      end

      it 'rejects a duplicate key nested in an object' do
        json = %q({"a":{"b":1,"b":2}})
        error = parse_error(json)
        expect(error.category).to eq(:duplicate_member)
        expect(error.position).to eq(json.index('"b"', 7))
      end

      it 'treats escaped and unescaped spellings of the same key as duplicates' do
        json = '{"\\u0061":1,"a":2}'
        error = parse_error(json)
        expect(error.category).to eq(:duplicate_member)
        expect(error.position).to eq(json.rindex('"a"'))
      end

      it 'treats two differently escaped spellings of the same key as duplicates' do
        json = '{"\\u0061":1,"\\u0061":2}'
        expect(parse_error(json).category).to eq(:duplicate_member)
      end

      it 'allows the same key in separate nested objects' do
        json = %q({"a":{"k":1},"b":{"k":2}})
        expect(described_class.parse(json)).to eq('a' => { 'k' => 1 }, 'b' => { 'k' => 2 })
      end

      it 'allows repeated values that are not keys' do
        json = %q({"a":"x","b":"x","c":["x",{"d":"x"}]})
        expect { described_class.parse(json) }.not_to raise_error
      end
    end

    context 'with structural limits' do
      it 'rejects nesting deeper than the maximum depth' do
        json = '[' * (max_depth + 1) + '1' + ']' * (max_depth + 1)
        expect(parse_error(json).category).to eq(:depth_exceeded)
      end

      it 'rejects more than the maximum number of object members' do
        json = members_json(max_members + 1)
        expect(parse_error(json).category).to eq(:too_many_members)
      end

      it 'does not let arrays bypass the object member limit' do
        json = %Q({"a":[#{members_json(max_members + 1)}]})
        expect(parse_error(json).category).to eq(:too_many_members)
      end

      it 'rejects a number longer than the maximum lexical length' do
        expect(parse_error('1' * (max_number_length + 1)).category).to eq(:number_too_long)
      end

      it 'counts the sign and exponent against the number length' do
        json = '-1.5e' + '0' * (max_number_length - 4)
        expect(parse_error(json).category).to eq(:number_too_long)
      end
    end

    context 'with invalid UTF-8' do
      it 'rejects an invalid continuation byte inside a string' do
        expect(parse_error(bytes(0x22, 0xff, 0x22)).category).to eq(:invalid_utf8)
      end

      it 'rejects an overlong UTF-8 sequence' do
        expect(parse_error(bytes(0x22, 0xc0, 0xaf, 0x22)).category).to eq(:invalid_utf8)
      end

      it 'rejects a UTF-8 encoded surrogate code point' do
        expect(parse_error(bytes(0x22, 0xed, 0xa0, 0x80, 0x22)).category).to eq(:invalid_utf8)
      end

      it 'rejects a truncated multibyte sequence' do
        expect(parse_error(bytes(0x22, 0xc3, 0x22)).category).to eq(:invalid_utf8)
      end

      it 'rejects invalid UTF-8 outside of strings' do
        expect(parse_error(bytes(0xff)).category).to eq(:invalid_utf8)
      end
    end

    context 'with malformed documents' do
      {
        'empty document' => ['', :unexpected_end],
        'trailing data' => ['{"a":1}x', :unexpected_token],
        'missing value' => ['{"a":}', :unexpected_token],
        'trailing comma in object' => ['{"a":1,}', :unexpected_token],
        'trailing comma in array' => ['[1,]', :unexpected_token],
        'missing comma' => ['[1 2]', :unexpected_token],
        'leading zero' => ['01', :unexpected_token],
        'unknown literal' => ['tru', :unexpected_token],
        'control character in string' => ["\"a#{0x00.chr}b\"", :unexpected_token],
        'unterminated unicode escape' => ['"\u"', :unexpected_end],
        'lone low surrogate' => ['"\udc00"', :unexpected_token],
        'lone high surrogate' => ['"\ud800"', :unexpected_token]
      }.each do |description, (input, category)|
        it "rejects #{description}" do
          expect(parse_error(input).category).to eq(category)
        end
      end
    end

    context 'error reporting' do
      it 'raises a JSON::ParserError' do
        expect { described_class.parse('{') }.to raise_error(::JSON::ParserError)
      end

      it 'exposes position and category' do
        error = parse_error(%q({"a":1,"a":2}))
        expect(error).to be_a(described_class::ParseError)
        expect(error.position).to be_an(Integer)
        expect(error.category).to be_a(Symbol)
      end

      it 'only mentions the category and position' do
        json = %q({"secret-key":"secret-value","secret-key":2})
        error = parse_error(json)
        expect(error.message).to match(/\AJSON parsing failed: \w+ at position \d+\z/)
        expect(error.message).not_to include('secret-key')
        expect(error.message).not_to include('secret-value')
      end
    end
  end

  def parse_error(json)
    described_class.parse(json)
    raise 'expected a parse error'
  rescue described_class::ParseError => e
    e
  end

  def bytes(*values)
    values.pack('C*')
  end

  def members_json(count)
    members = (1..count).map { |index| %Q("k#{index}":#{index}) }
    "{#{members.join(',')}}"
  end

  def max_depth
    described_class.const_get(:MAX_DEPTH)
  end

  def max_members
    described_class.const_get(:MAX_OBJECT_MEMBERS)
  end

  def max_number_length
    described_class.const_get(:MAX_NUMBER_LENGTH)
  end
end
