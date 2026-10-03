# frozen_string_literal: true
require 'support'
require 'mustermann'
require 'mustermann/simple'
require 'mustermann/shell'
require 'mustermann/template'

describe 'unicode normalization' do
  let(:nfc_path) { "/caf\u00e9" }
  let(:nfd_path) { "/cafe\u0301" }

  describe Mustermann::Simple do
    it 'matches both encodings' do
      pattern = Mustermann::Simple.new(nfd_path, unicode_normalize: :nfc)
      pattern.to_s.should be == nfd_path
      pattern.should match('/caf%C3%A9')
      pattern.should match('/caf%65%CC%81')
    end
  end

  describe Mustermann::Shell do
    it 'matches both encodings' do
      pattern = Mustermann::Shell.new(nfd_path, unicode_normalize: :nfc)
      pattern.to_s.should be == nfd_path
      pattern.should match(nfc_path)
      pattern.should match(nfd_path)
      pattern.should_not match('/cafe')
    end
  end

  describe Mustermann::Template do
    it 'matches both encodings and expands to the normalized form' do
      pattern = Mustermann::Template.new("/cafe\u0301/{name}", unicode_normalize: :nfc)
      pattern.should match("/caf\u00e9/x")
      pattern.should match("/cafe\u0301/x")
      pattern.expand(name: 'x').should be == '/caf%C3%A9/x'
    end
  end
end
