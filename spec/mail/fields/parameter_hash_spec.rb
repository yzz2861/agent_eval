# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ParameterHash do
  it "should return the values in the hash" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'value2' => 'two'})
    expect(hash.keys).to include("value1")
    expect(hash.keys).to include("value2")
    expect(hash.values).to include('one')
    expect(hash.values).to include('two')
  end

  it "should return the values in the hash regardless of symbol or string" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'value2' => 'two'})
    expect(hash['value1']).to eq 'one'
    expect(hash['value2']).to eq 'two'
    expect(hash[:value1]).to eq 'one'
    expect(hash[:value2]).to eq 'two'
  end

  it "should return the values in the hash using case-insensitive key matching" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'VALUE2' => 'two'})
    expect(hash['VALUE1']).to eq 'one'
    expect(hash['vAlUe2']).to eq 'two'
    expect(hash[:VaLuE1]).to eq 'one'
    expect(hash[:value2]).to eq 'two'
  end

  it "should return the correct value if they are not encoded" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value1' => 'one', 'value2' => 'two'})
    expect(hash['value1']).to eq 'one'
    expect(hash['value2']).to eq 'two'
  end

  it "should return a name list concatenated" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*1' => 'one', 'value*2' => 'two'})
    expect(hash['value']).to eq 'onetwo'
  end

  it "should return a name list concatenated and unencoded" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*0*' => "us-ascii'en'This%20is%20even%20more%20",
                 'value*1*' => "%2A%2A%2Afun%2A%2A%2A%20",
                 'value*2'  => "isn't it"})
    expect(hash['value']).to eq "This is even more ***fun*** isn't it"
  end

  describe "#strict_decode" do
    it "supports parser-style pairs with duplicate raw keys" do
      result = described_class.strict_decode([
        { 'filename*0*' => "utf-8''first" },
        { 'filename*1' => 'tail' },
        { 'filename*1' => 'other-tail' }
      ])

      expect(result.parameters).to be_empty
      expect(result.diagnostics.first.type).to eq :duplicate_section
    end

    it "decodes RFC 2231 bytes after all sections are merged" do
      hash = Mail::ParameterHash.new
      hash.merge!({
        'filename*0*' => "utf-8''%E4%BD",
        'filename*1'  => '%A0',
        'filename*2'  => '%E5%A5%BD'
      })

      result = hash.strict_decode

      expect(result.parameters['filename']).to eq '你好'
      expect(result.diagnostics).to be_empty
    end

    it "accepts the RFC 2231 example with extended then unmarked sections" do
      hash = Mail::ParameterHash.new
      hash.merge!('title*0*' => "us-ascii'en'This%20is%20even%20more%20")
      hash.merge!('title*1*' => '%2A%2A%2Afun%2A%2A%2A%20')
      hash.merge!('title*2' => "isn't it")

      result = hash.strict_decode

      expect(result.parameters['title']).to eq "This is even more ***fun*** isn't it"
      expect(result.diagnostics).to be_empty
    end

    it "reports duplicate sections and retains every conflicting raw fragment" do
      hash = Mail::ParameterHash.new
      hash.merge!('filename*0*' => "utf-8''first")
      hash.merge!('filename*1' => 'tail')
      hash.merge!('filename*1' => 'other-tail')

      result = hash.strict_decode
      diagnostic = result.diagnostics.first

      expect(result.parameters).to be_empty
      expect(diagnostic.type).to eq :duplicate_section
      expect(diagnostic.parameter).to eq 'filename'
      expect(diagnostic.details[:section]).to eq 1
      expect(diagnostic.raw_fragments.map { |fragment| fragment[:key] }).to eq ['filename*1', 'filename*1']
      expect(diagnostic.raw_fragments.map { |fragment| fragment[:value] }).to eq ['tail', 'other-tail']
    end

    it "reports broken section sequences with enough detail to locate the parameter" do
      hash = Mail::ParameterHash.new
      hash.merge!({
        'filename*0*' => "utf-8''first",
        'filename*2'  => 'third'
      })

      result = hash.strict_decode
      diagnostic = result.diagnostics.first

      expect(result.parameters).to be_empty
      expect(diagnostic.type).to eq :broken_sections
      expect(diagnostic.parameter).to eq 'filename'
      expect(diagnostic.details[:missing_sections]).to eq [1]
      expect(diagnostic.details[:present_sections]).to eq [0, 2]
      expect(diagnostic.raw_fragments.first[:key]).to eq 'filename*0*'
    end

    it "reports each invalid percent escape with fragment and byte offset" do
      hash = Mail::ParameterHash.new
      hash.merge!({
        'filename*0*' => "utf-8''good%20bad%ZZ%",
        'filename*1'  => '%4tail'
      })

      result = hash.strict_decode
      diagnostics = result.diagnostics

      expect(result.parameters).to be_empty
      expect(diagnostics.map(&:type)).to eq [
        :invalid_percent_encoding,
        :invalid_percent_encoding,
        :invalid_percent_encoding
      ]
      expect(diagnostics[0].details).to include(section: 0, occurrence: 0, byte_offset: 17)
      expect(diagnostics[0].raw_fragments.first[:value]).to eq "utf-8''good%20bad%ZZ%"
      expect(diagnostics[1].details).to include(section: 0, occurrence: 0, byte_offset: 20)
      expect(diagnostics[2].details).to include(section: 1, occurrence: 1, byte_offset: 0)
      expect(diagnostics[2].raw_fragments.first[:value]).to eq '%4tail'
    end

    it "reports unsupported charsets without warning" do
      hash = Mail::ParameterHash.new
      hash.merge!('filename*' => "x-unknown-charset''file%20name")

      result = hash.strict_decode
      diagnostic = result.diagnostics.first

      expect(result.parameters).to be_empty
      expect(diagnostic.type).to eq :unsupported_charset
      expect(diagnostic.details[:charset]).to eq 'x-unknown-charset'
      expect(diagnostic.raw_fragments.first[:key]).to eq 'filename*'
    end

    it "reports invalid byte sequences after segments are merged" do
      hash = Mail::ParameterHash.new
      hash.merge!('filename*' => "utf-8''%FF")

      result = hash.strict_decode
      diagnostic = result.diagnostics.first

      expect(result.parameters).to be_empty
      expect(diagnostic.type).to eq :invalid_byte_sequence
      expect(diagnostic.details[:charset]).to eq 'utf-8'
      expect(diagnostic.raw_fragments.first[:value]).to eq "utf-8''%FF"
    end

    it "reports conflicts between ordinary and extended parameters" do
      hash = Mail::ParameterHash.new
      hash.merge!({
        'filename'    => 'plain.pdf',
        'filename*0*' => "utf-8''extended",
        'filename*1'  => '.pdf'
      })

      result = hash.strict_decode
      diagnostic = result.diagnostics.first

      expect(result.parameters).to be_empty
      expect(diagnostic.type).to eq :parameter_conflict
      expect(diagnostic.parameter).to eq 'filename'
      expect(diagnostic.raw_fragments.map { |fragment| fragment[:key] }).to eq [
        'filename',
        'filename*0*',
        'filename*1'
      ]
      expect(diagnostic.details[:plain_fragments].first[:value]).to eq 'plain.pdf'
      expect(diagnostic.details[:sectioned_fragments].map { |fragment| fragment[:section] }).to eq [0, 1]
    end

    it "can decode a single requested parameter and return its diagnostics" do
      hash = Mail::ParameterHash.new
      hash.merge!({
        'filename*0*' => "utf-8''%E4%BD",
        'filename*1'  => '%A0',
        'other'       => 'value'
      })

      result = hash.strict_decode('FILENAME')

      expect(result.parameters.keys).to eq ['filename']
      expect(result.parameters['filename']).to eq '你'
      expect(result.parameters).not_to include('other')
    end
  end

  it "allows for blank language" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "us-ascii''Hello%20there"})
    expect(hash['value']).to eq "Hello there"
  end

  it "allows for blank charset" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "'en'Hello%20there"})
    expect(hash['value']).to eq "Hello there"
  end

  it "allows for blank charset and language" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "''Hello%20there"})
    expect(hash['value']).to eq "Hello there"
  end

  it "converts from specified encoding to utf-8" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*' => "iso-8859-1'en'H%EBll%F3%20there"})
    expect(hash['value']).to eq "Hëlló there"
  end

  it "should allow us to add a value" do
    hash = Mail::ParameterHash.new
    hash['value'] = 'bob'
    expect(hash['value']).to eq 'bob'
  end

  it "should return an encoded value" do
    hash = Mail::ParameterHash.new
    hash.merge!({'value*0*' => "us-ascii'en'This%20is%20even%20more%20",
                 'value*1*' => "%2A%2A%2Afun%2A%2A%2A%20",
                 'value*2'  => "isn't it"})
    expect(hash.encoded).to eq %Q{value*0*=us-ascii'en'This%20is%20even%20more%20;\r\n\svalue*1*=%2A%2A%2Afun%2A%2A%2A%20;\r\n\svalue*2="isn't it"}
  end

end
