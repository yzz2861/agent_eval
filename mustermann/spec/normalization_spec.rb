# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/match'
require 'mustermann/set'

describe 'Unicode normalization option' do
  let(:nfc) { "\u00e9" }
  let(:nfd) { "e\u0301" }

  describe Mustermann::Pattern do
    example 'accepts :nfc' do
      pattern = Mustermann::Sinatra.new('/:name', normalization: :nfc)
      pattern.normalization.should be == :nfc
      pattern.should be_normalize
    end

    example 'is disabled by default' do
      Mustermann::Sinatra.new('/:name').should_not be_normalize
    end

    example 'accepts nil and false to disable normalization' do
      Mustermann::Sinatra.new('/:name', normalization: nil).normalization.should be_nil
      Mustermann::Sinatra.new('/:name', normalization: false).normalization.should be_nil
    end

    example 'raises for unsupported normalization forms' do
      expect { Mustermann::Sinatra.new('/:name', normalization: :nfd) }.
        to raise_error(ArgumentError, /unsupported Unicode normalization form :nfd/)
      expect { Mustermann::Sinatra.new('/:name', normalization: :nfkc) }.
        to raise_error(ArgumentError)
    end

    example 'is part of the pattern options and cache key' do
      Mustermann::Sinatra.new('/:name', normalization: :nfc).
        should_not be == Mustermann::Sinatra.new('/:name')
      Mustermann::Sinatra.new('/:name', normalization: :nfc).
        should be_equal Mustermann::Sinatra.new('/:name', normalization: :nfc)
    end
  end

  describe 'matching' do
    subject(:pattern) { Mustermann.new("/caf#{nfc}/:id", normalization: :nfc) }

    example 'matches composed and decomposed raw paths' do
      pattern.should     match("/caf#{nfc}/42")
      pattern.should     match("/caf#{nfd}/42")
    end

    example 'matches all percent-encoded variants of the multi-byte character' do
      pattern.should     match('/caf%C3%A9/42')
      pattern.should     match('/caf%c3%a9/42')
      pattern.should     match('/cafe%CC%81/42')
      pattern.should     match('/cafe%cc%81/42')
      pattern.should     match('/caf%65%CC%81/42')
    end

    example 'does not match the base character without its combining mark' do
      pattern.should_not match('/cafe/42')
      pattern.should_not match('/caf%65/42')
      pattern.should_not match("/caf#{nfd}x/42")
    end

    example 'matches a decomposed pattern against composed input' do
      decomposed = Mustermann.new("/caf#{nfd}/:id", normalization: :nfc)
      decomposed.should match("/caf#{nfc}/42")
      decomposed.should match('/caf%C3%A9/42')
      decomposed.should match('/cafe%CC%81/42')
      decomposed.to_s.bytes.should be == "/caf#{nfd}/:id".bytes
    end

    example 'does not normalize without the option' do
      plain = Mustermann.new("/caf#{nfc}/:id")
      plain.should     match("/caf#{nfc}/42")
      plain.should_not match("/caf#{nfd}/42")
    end

    example 'does not lowercase anything' do
      uppercase = Mustermann.new('/CAF', normalization: :nfc)
      uppercase.should     match('/CAF')
      uppercase.should_not match('/caf')
    end

    example 'supports optional segments' do
      optional = Mustermann.new("/caf#{nfc}(/:lang)?", normalization: :nfc)
      optional.should match("/caf#{nfd}")
      optional.should match("/caf#{nfd}/en")
      optional.params("/caf#{nfd}/en").should be == { 'lang' => 'en' }
    end

    example 'supports peeking' do
      peeked = pattern.peek_match("/cafe%CC%81/42/more")
      peeked.to_s.should be == "/cafe%CC%81/42"
      peeked.post_match.should be == '/more'
    end

    example 'matches constraints given as strings' do
      constrained = Mustermann.new('/:lang', capture: nfc, normalization: :nfc)
      constrained.should     match("/#{nfd}")
      constrained.should     match("/#{nfc}")
      decomposed = Mustermann.new('/:lang', capture: nfd, normalization: :nfc)
      decomposed.should     match("/#{nfc}")
    end

    example 'leaves regular expression syntax untouched' do
      regexp = Mustermann.new(%r{/users/(?<name>\d+)}, normalization: :nfc)
      regexp.should     match('/users/42')
      regexp.should_not match('/users/ab')
    end
  end

  describe 'captures' do
    subject(:pattern) { Mustermann.new('/users/:name', normalization: :nfc) }

    example 'keep the original string and raw capture values' do
      match = pattern.match("/users/#{nfd}")
      match.string.should       be == "/users/#{nfd}"
      match[:name].should       be == nfd
      match[:name].bytes.should be == nfd.bytes
      match.params['name'].should be == nfd
    end

    example 'expose normalized capture values' do
      match = pattern.match("/users/#{nfd}")
      match.normalized_params['name'].should be == nfc
      match.normalized_captures.should       be == [nfc]
      pattern.normalized_params("/users/#{nfd}")['name'].should be == nfc
    end

    example 'keep percent-encoded captures raw but normalize on demand' do
      match = pattern.match('/users/e%CC%81')
      match['name'].should be == 'e%CC%81'
      match.normalized_params['name'].should be == nfc
    end

    example 'normalizes splats' do
      splat = Mustermann.new('/files/*rest', normalization: :nfc)
      match = splat.match("/files/a/b/#{nfd}")
      match[:rest].should             be == "a/b/#{nfd}"
      match.normalized_params['rest'].should be == "a/b/#{nfc}"
      anonymous = Mustermann.new('/files/*', normalization: :nfc)
      anonymous_match = anonymous.match("/files/#{nfd}")
      anonymous_match.normalized_params['splat'].should be == [nfc]
    end

    example 'leave nil optional captures untouched' do
      optional = Mustermann.new("/caf#{nfc}(/:lang)?", normalization: :nfc)
      match = optional.match("/caf#{nfd}")
      match.normalized_params['lang'].should be_nil
    end

    example 'leave non-string captures (e.g. typed captures) untouched' do
      pattern = Mustermann.new('/:id', capture: Integer, normalization: :nfc)
      pattern.normalized_params('/42').should be == { 'id' => 42 }
    end
  end

  describe 'invalid encoding' do
    subject(:pattern) { Mustermann.new('/:name', normalization: :nfc) }

    example 'raises a clear error for invalid percent-encoded bytes on matching' do
      expect { pattern === '/%FF' }.to     raise_error(Mustermann::NormalizeError, /invalid byte sequence/)
      expect { pattern.match('/%FF') }.to   raise_error(Mustermann::NormalizeError)
      expect { pattern.params('/%FF') }.to  raise_error(Mustermann::NormalizeError)
      expect { pattern.peek_match('/%FF') }.to raise_error(Mustermann::NormalizeError)
      expect { pattern =~ '/%FF' }.to       raise_error(Mustermann::NormalizeError)
    end

    example 'raises a clear error for invalid raw byte sequences' do
      bad = "/fo\xFF".dup.force_encoding('UTF-8')
      expect { pattern.match(bad) }.to raise_error(Mustermann::NormalizeError, /NFC/)
    end

    example 'raises for binary-encoded strings' do
      binary = '/foo'.dup.force_encoding('ASCII-8BIT')
      expect { pattern === binary }.to raise_error(Mustermann::NormalizeError)
    end

    example 'does not cache invalid strings as successful matches' do
      3.times { expect { pattern.match('/%FF') }.to raise_error(Mustermann::NormalizeError) }
      pattern.match('/foo').should be_a(Mustermann::Match)
    end
  end

  describe 'expansion' do
    example 'produces canonical NFC output from decomposed values' do
      pattern = Mustermann.new('/users/:name', normalization: :nfc)
      pattern.expand(name: nfd).should be == '/users/%C3%A9'
      pattern.expand(name: nfc).should be == '/users/%C3%A9'
    end

    example 'produces canonical output from a decomposed literal' do
      pattern = Mustermann.new("/caf#{nfd}/:id", normalization: :nfc)
      pattern.expand(id: '42').should be == '/caf%C3%A9/42'
    end

    example 'leaves expansion untouched without the option' do
      Mustermann.new('/users/:name').expand(name: nfd).should be == '/users/e%CC%81'
    end

    example 'is supported by an explicit expander' do
      expander = Mustermann::Expander.new('/users/:name', normalization: :nfc)
      expander.expand(name: nfd).should be == '/users/%C3%A9'
    end

    example 'round-trips the two visually identical paths through the same route' do
      pattern = Mustermann.new("/caf#{nfc}/:id", normalization: :nfc)
      path_nfc = "/caf#{nfc}/42"
      path_nfd = '/cafe%CC%81/42'
      pattern.should     match(path_nfc)
      pattern.should     match(path_nfd)
      pattern.expand(id: '42').should be == '/caf%C3%A9/42'
    end
  end

  describe 'pattern types' do
    example 'supports identity patterns' do
      pattern = Mustermann.new("/caf#{nfc}", type: :identity, normalization: :nfc)
      pattern.should     match("/caf#{nfd}")
      pattern.should     match('/cafe%CC%81')
      pattern.should_not match('/cafe')
      pattern.peek_size("/cafe%CC%81/rest").should be == 11
      pattern.peek_size("/caf#{nfd}/rest").should be == 6
      pattern.expand.should be == "/caf#{nfc}"
      pattern.expand(:append, name: nfd).should be == "/caf#{nfc}?name=%C3%A9"
    end

    example 'supports shell patterns' do
      pattern = Mustermann.new("/caf#{nfc}*", type: :shell, normalization: :nfc)
      pattern.should     match("/caf#{nfd}erie")
      pattern.should     match('/cafe%CC%81erie')
      expect { pattern.match('/caf%FF') }.to raise_error(Mustermann::NormalizeError)
      pattern.peek_size('/cafe%CC%81erie').should be == 15
      pattern.peek_size("/caf#{nfd}erie").should be == 9
      pattern.peek_size('/nope').should be_nil
      expect { pattern.peek_size('/caf%FF') }.to raise_error(Mustermann::NormalizeError)
    end

    example 'handles long combining sequences without generating an exponential regexp' do
      long_nfd = 'a' + ("\u0301" * 11)
      pattern = Mustermann.new("/#{long_nfd}", type: :sinatra, normalization: :nfc)
      pattern.should match("/#{long_nfd.unicode_normalize(:nfc)}")
      repeated = Mustermann.new("/#{nfd}-#{nfd}", normalization: :nfc)
      repeated.should match("/#{nfc}-#{nfc}")
      repeated.should match('/e%CC%81-e%CC%81')
      variants = Mustermann::Unicode.representations("#{nfd}-#{nfd}", :nfc)
      variants.should include("#{nfc}-#{nfc}")
      variants.should include('e%CC%81-e%CC%81')
      variants.should include('e%CC%81%2De%CC%81')
      variants.should include("#{nfc}-%C3%A9")
    end

    example 'treats Hangul jamo as the same cluster as their composed syllable' do
      jamo = "\u1100\u1161"
      syllable = jamo.unicode_normalize(:nfc)
      pattern = Mustermann.new("/#{jamo}/:id", normalization: :nfc)
      pattern.should match("/#{syllable}/1")
      pattern.should match('/%EA%B0%80/1')
      pattern.should_not match('/%E1%84%80/1')
      pattern.expand(id: '1').should be == '/%EA%B0%80/1'
    end

    example 'supports simple patterns' do
      pattern = Mustermann.new("/caf#{nfc}/:id", type: :simple, normalization: :nfc)
      pattern.should     match("/caf#{nfd}/42")
      pattern.normalized_params('/cafe%CC%81/42').should be == { 'id' => '42' }
    end

    example 'supports template patterns' do
      pattern = Mustermann.new("/caf#{nfc}/{id}", type: :template, normalization: :nfc)
      pattern.should     match('/cafe%CC%81/42')
      pattern.expand(id: '42').should be == '/caf%C3%A9/42'
    end

    example 'supports uri_decode: false for raw forms' do
      pattern = Mustermann.new("/caf#{nfc}", normalization: :nfc, uri_decode: false)
      pattern.should     match("/caf#{nfd}")
      pattern.should_not match('/cafe%CC%81')
    end
  end

  describe Mustermann::Set do
    example 'routes both encodings to the same pattern without trie dispatch' do
      set = Mustermann::Set.new(normalization: :nfc)
      set.add("/caf#{nfc}/:id", :show)
      set.match("/caf#{nfd}/42").value.should be == :show
      set.match('/cafe%CC%81/42').value.should be == :show
    end

    example 'keeps linear dispatch even when the trie is requested' do
      set = Mustermann::Set.new(use_trie: true, normalization: :nfc)
      set.add("/caf#{nfc}/:id", :show)
      set.match("/caf#{nfd}/42").value.should be == :show
    end
  end
end
