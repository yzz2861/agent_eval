# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/sinatra'
require 'mustermann/regular'
require 'mustermann/identity'

describe 'unicode normalization' do
  # The two paths below look identical but use different Unicode encodings:
  # NFC (precomposed) and NFD (decomposed, combining accent).
  let(:nfc_path) { "/caf\u00e9" }
  let(:nfd_path) { "/cafe\u0301" }

  it 'is disabled by default' do
    pattern = Mustermann.new(nfd_path)
    pattern.unicode_normalize.should be_nil
    pattern.should     match(nfd_path)
    pattern.should_not match(nfc_path)
  end

  it 'accepts true as alias for :nfc' do
    Mustermann.new(nfd_path, unicode_normalize: true).unicode_normalize.should be == :nfc
  end

  it 'raises an ArgumentError for unsupported normalization forms' do
    expect { Mustermann.new(nfd_path, unicode_normalize: :nfd) }.to raise_error(ArgumentError, /nfc/)
  end

  it 'is a supported option on all patterns' do
    Mustermann::Pattern.supported?(:unicode_normalize).should be == true
  end

  describe 'matching' do
    subject(:pattern) { Mustermann.new(nfd_path, unicode_normalize: :nfc) }

    it 'matches the same path in NFC and NFD encoding' do
      pattern.should match(nfc_path)
      pattern.should match(nfd_path)
    end

    it 'matches a pattern in NFC encoding against an NFD path' do
      nfc_pattern = Mustermann.new(nfc_path, unicode_normalize: :nfc)
      nfc_pattern.should match(nfc_path)
      nfc_pattern.should match(nfd_path)
    end

    it 'does not change the case of any characters' do
      pattern = Mustermann.new("/CAF\u00c9", unicode_normalize: :nfc)
      pattern.should     match("/CAF\u00c9")
      pattern.should     match("/CAFE\u0301")
      pattern.should_not match(nfc_path)
      pattern.should_not match(nfd_path)
    end

    it 'supports =~' do
      (pattern =~ nfc_path).should be == 0
      (pattern =~ nfd_path).should be == 0
      (pattern =~ '/other').should be_nil
    end

    it 'supports peeking' do
      pattern = Mustermann.new('/:name', unicode_normalize: :nfc)
      pattern.peek("/caf\u00e9/x").should be == "/caf\u00e9"
      pattern.peek("/cafe\u0301/x").should be == "/cafe\u0301"
      pattern.peek_size("/cafe\u0301/x").should be == 6
    end
  end

  describe 'original string and captures' do
    subject(:pattern) { Mustermann.new('/:name', unicode_normalize: :nfc) }

    it 'keeps the original string on the match' do
      match = pattern.match(nfd_path)
      match.string.should be == nfd_path
      match.to_s.should be == nfd_path
    end

    it 'exposes the normalized string on the match' do
      match = pattern.match(nfd_path)
      match.normalized_string.should be == nfc_path
    end

    it 'lets the caller pick original or normalized capture values' do
      match = pattern.match(nfd_path)
      match.params.should be == { 'name' => "cafe\u0301" }
      match.params['name'].should_not be == "caf\u00e9"
      match.normalized_params.should be == { 'name' => "caf\u00e9" }
    end

    it 'maps capture ranges back to the original string' do
      match = pattern.match("/cafe\u0301")
      match.params['name'].should be == "cafe\u0301"
      match = pattern.match("/caf\u00e9")
      match.params['name'].should be == "caf\u00e9"
    end

    it 'keeps original captures when the normalization only affects literals' do
      pattern = Mustermann.new("/caf\u00e9/:name", unicode_normalize: :nfc)
      match = pattern.match("/cafe\u0301/b\u00fcch")
      match.params.should be == { 'name' => "b\u00fcch" }
      match.normalized_params.should be == { 'name' => "b\u00fcch" }
    end

    it 'returns nil normalized values when normalization is disabled' do
      match = Mustermann.new('/:name').match(nfc_path)
      match.normalized_string.should be_nil
      match.normalized_params.should be_nil
    end

    it 'maps splat captures back to the original string' do
      pattern = Mustermann.new('/*', unicode_normalize: :nfc)
      match = pattern.match("/cafe\u0301/x")
      match.params.should be == { 'splat' => ["cafe\u0301/x"] }
      match.normalized_params.should be == { 'splat' => ["caf\u00e9/x"] }
    end

    it 'works with the match cache disabled' do
      pattern = Mustermann.new('/:name', unicode_normalize: :nfc, cache: false)
      match = pattern.match("/cafe\u0301")
      match.params.should be == { 'name' => "cafe\u0301" }
      match.normalized_params.should be == { 'name' => "caf\u00e9" }
    end
  end

  describe 'percent encoded multibyte characters' do
    subject(:pattern) { Mustermann.new(nfd_path, unicode_normalize: :nfc) }

    it 'matches percent encoded NFC input' do
      pattern.should match('/caf%C3%A9')
      pattern.should match('/caf%c3%a9')
    end

    it 'matches percent encoded NFD input' do
      pattern.should match('/caf%65%CC%81')
      pattern.should match('/caf%65%cc%81')
    end

    it 'decodes captures from percent encoded input' do
      pattern = Mustermann.new('/:name', unicode_normalize: :nfc)
      pattern.params('/caf%C3%A9').should be == { 'name' => "caf\u00e9" }
      match = pattern.match('/caf%65%CC%81')
      match.params['name'].should be == "cafe\u0301"
      match.normalized_params['name'].should be == "caf\u00e9"
    end

    it 'does not match percent encoded input when uri_decode is disabled' do
      pattern = Mustermann.new(nfd_path, unicode_normalize: :nfc, uri_decode: false)
      pattern.should     match(nfc_path)
      pattern.should_not match('/caf%C3%A9')
    end
  end

  describe 'optional segments' do
    subject(:pattern) { Mustermann.new("/cafe\u0301(.:ext)?", unicode_normalize: :nfc) }

    it 'matches with and without the optional segment in both encodings' do
      pattern.should match("/caf\u00e9")
      pattern.should match("/cafe\u0301")
      pattern.should match("/caf\u00e9.png")
      pattern.should match("/cafe\u0301.png")
      pattern.params("/cafe\u0301.png").should be == { 'ext' => 'png' }
    end
  end

  describe 'pattern caching' do
    it 'returns the same instance for identical string and options' do
      a = Mustermann::Sinatra.new(nfd_path, unicode_normalize: :nfc)
      b = Mustermann::Sinatra.new(nfd_path, unicode_normalize: :nfc)
      a.should be_equal(b)
    end

    it 'does not share instances between different option values' do
      a = Mustermann::Sinatra.new(nfd_path, unicode_normalize: :nfc)
      b = Mustermann::Sinatra.new(nfd_path)
      a.should_not be_equal(b)
      b.should_not match(nfc_path)
      a.should match(nfc_path)
    end

    it 'does not share the AST cache between normalized and unnormalized patterns' do
      plain      = Mustermann::Sinatra.new(nfd_path)
      normalized = Mustermann::Sinatra.new(nfd_path, unicode_normalize: :nfc)
      plain.should_not match(nfc_path)
      normalized.should match(nfc_path)
      plain.should match(nfd_path)
      normalized.should match(nfd_path)
    end

    it 'caches matches per pattern instance' do
      pattern = Mustermann::Sinatra.new(nfd_path, unicode_normalize: :nfc)
      pattern.match(nfc_path).should be_equal(pattern.match(nfc_path))
    end
  end

  describe 'expanding' do
    subject(:pattern) { Mustermann.new("/cafe\u0301/:name", unicode_normalize: :nfc) }

    # Expansion percent-encodes non-ASCII characters (existing Mustermann
    # convention); with normalization enabled, the encoded bytes are NFC.
    it 'expands to the normalized form' do
      pattern.expand(name: 'x').should be == '/caf%C3%A9/x'
    end

    it 'matches its own expansion in both encodings' do
      expanded = pattern.expand(name: 'x')
      expanded.should be == '/caf%C3%A9/x'
      pattern.should match(expanded)
      pattern.should match("/cafe\u0301/x")
      pattern.should match("/caf\u00e9/x")
    end

    it 'produces expansions that are visually identical regardless of the pattern encoding' do
      nfc_pattern = Mustermann.new("/caf\u00e9/:name", unicode_normalize: :nfc)
      nfd_pattern = Mustermann.new("/cafe\u0301/:name", unicode_normalize: :nfc)
      nfc_pattern.expand(name: 'x').should be == nfd_pattern.expand(name: 'x')
    end
  end

  describe Mustermann::Regular do
    it 'does not treat regexp syntax as normal text' do
      pattern = Mustermann::Regular.new('/caf.(x)?', unicode_normalize: :nfc)
      pattern.to_s.should be == '/caf.(x)?'
      pattern.should match('/cafex')
      pattern.should_not match('/cafexx')
    end

    it 'normalizes the matched string but not the regexp source' do
      pattern = Mustermann::Regular.new("/caf\u00e9/x", unicode_normalize: :nfc)
      pattern.regexp.source.should include("caf\u00e9")
      pattern.regexp.source.should_not include("cafe\u0301")
      pattern.should match("/caf\u00e9/x")
      pattern.should match("/cafe\u0301/x")
    end
  end

  describe Mustermann::Identity do
    it 'matches both encodings' do
      pattern = Mustermann::Identity.new(nfd_path, unicode_normalize: :nfc)
      pattern.should match(nfc_path)
      pattern.should match(nfd_path)
      pattern.to_s.should be == nfd_path
    end
  end

  describe 'invalid input' do
    it 'raises a Mustermann::Error for patterns with invalid encoding' do
      invalid = "/caf\xff".dup.force_encoding(Encoding::UTF_8)
      expect { Mustermann.new(invalid, unicode_normalize: :nfc) }.to raise_error(Mustermann::Error, /normaliz/i)
    end

    it 'raises a Mustermann::Error for input with invalid encoding' do
      pattern = Mustermann.new('/:name', unicode_normalize: :nfc)
      invalid = "/caf\xff".dup.force_encoding(Encoding::UTF_8)
      expect { pattern === invalid }.to raise_error(Mustermann::Error, /normaliz/i)
      expect { pattern.match invalid }.to raise_error(Mustermann::Error, /normaliz/i)
      expect { pattern.params invalid }.to raise_error(Mustermann::Error, /normaliz/i)
    end

    it 'raises a Mustermann::Error for input with an unsupported encoding' do
      pattern = Mustermann.new('/:name', unicode_normalize: :nfc)
      expect { pattern === '/caf'.encode(Encoding::SHIFT_JIS) }.to raise_error(Mustermann::Error, /normaliz/i)
    end

    it 'treats binary input as UTF-8' do
      pattern = Mustermann.new(nfc_path, unicode_normalize: :nfc)
      pattern.should match("/caf\xC3\xA9".b)
      expect { pattern === "/caf\xFF".b }.to raise_error(Mustermann::Error, /normaliz/i)
    end
  end

  describe 'invalid option values' do
    it 'raises an ArgumentError' do
      expect { Mustermann.new('/foo', unicode_normalize: :nfd)  }.to raise_error(ArgumentError)
      expect { Mustermann.new('/foo', unicode_normalize: 'nfc') }.to raise_error(ArgumentError)
    end
  end

  describe Mustermann::Set do
    it 'matches both encodings even when the trie matcher would be used' do
      set = Mustermann::Set.new(use_trie: true)
      set.add("/cafe\u0301/:name", :route)
      set.match("/caf\u00e9/x").should be_nil
      set = Mustermann::Set.new(use_trie: true, unicode_normalize: :nfc)
      set.add("/cafe\u0301/:name", :route)
      set.match("/caf\u00e9/x").value.should be == :route
      set.match("/cafe\u0301/x").value.should be == :route
      set.match("/caf\u00e9/x").params.should be == { 'name' => 'x' }
    end
  end
end
