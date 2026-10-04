# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ParameterDecoder do
  describe '.decode in lenient mode (default behavior)' do
    it 'returns a plain IndifferentHash with no diagnostics' do
      result = described_class.decode([{'name' => 'value'}])
      expect(result).to be_a(Mail::IndifferentHash)
      expect(result['name']).to eq 'value'
    end

    it 'accepts key/value pairs as well as single-key hashes' do
      expect(described_class.decode([['name', 'value']])['name']).to eq 'value'
    end

    it 'joins RFC 2231 continuation segments' do
      result = described_class.decode([
        {'value*1' => 'one'}, {'value*2' => 'two'}
      ])
      expect(result['value']).to eq 'onetwo'
    end

    it 'tolerates duplicate segments and gaps like ParameterHash does' do
      result = described_class.decode([
        {'value*0' => 'a'}, {'value*0' => 'b'}, {'value*2' => 'c'}
      ])
      expect(result['value']).to eq 'abc'
    end

    it 'keeps charset/percent decoding after byte-level merge' do
      pairs = [
        {'value*0*' => "utf-8''%E4%B8"},
        {'value*1*' => "%AD%E6%96%87"}
      ]
      expect(described_class.decode(pairs)['value']).to eq '中文'
    end

    it 'does not flag literal percent signs in plain parameters' do
      result = described_class.decode([{'value' => '100% done'}])
      expect(result['value']).to eq '100% done'
    end
  end

  describe '.decode strict mode' do
    it 'returns a valid result for well-formed extended parameters' do
      pairs = [
        {'filename*0*' => "us-ascii'en'This%20is%20even%20more%20"},
        {'filename*1*' => '%2A%2A%2Afun%2A%2A%2A%20'},
        {'filename*2'  => "isn't it"}
      ]
      result = described_class.decode(pairs, strict: true, field: 'Content-Type')
      expect(result).to be_a(Mail::ParameterDecodeResult)
      expect(result).to be_valid
      expect(result.diagnostics).to eq []
      expect(result.parameters['filename']).to eq 'This is even more ***fun*** isn\'t it'
    end

    it 'decodes a multi-byte character split across two segments' do
      pairs = [
        {'name*0*' => "utf-8''%E4%B8"},
        {'name*1*' => '%AD%E6%96%87'}
      ]
      result = described_class.decode(pairs, strict: true)
      expect(result).to be_valid
      expect(result.parameters['name']).to eq '中文'
    end

    it 'reports duplicate segment indices with the raw fragments' do
      pairs = [
        {'f*0*' => "utf-8''a"},
        {'f*0*' => "utf-8''b"},
        {'f*1*' => 'c'}
      ]
      result = described_class.decode(pairs, strict: true)
      expect(result).not_to be_valid
      diag = result.diagnostics.find { |d| d.code == :duplicate_segment }
      expect(diag.parameter).to eq 'f'
      expect(diag.segment).to eq 0
      expect(diag.position).to eq 1 # the offending second occurrence
      expect(diag.raw_segments).to eq ["f*0*=utf-8''a", "f*0*=utf-8''b"]
    end

    it 'reports every missing segment when continuation indices are gapped' do
      pairs = [
        {'f*0*' => "utf-8''a"},
        {'f*2*' => 'c'},
        {'f*4*' => 'e'}
      ]
      result = described_class.decode(pairs, strict: true)
      gaps = result.diagnostics.select { |d| d.code == :segment_gap }
      expect(gaps.map(&:segment)).to eq [1, 3]
      expect(gaps.map(&:parameter).uniq).to eq ['f']
      expect(gaps.first.position).to eq 0
    end

    it 'reports a continuation that does not start at zero' do
      result = described_class.decode([{'f*1*' => "utf-8''a"}], strict: true)
      diag = result.diagnostics.find { |d| d.code == :segment_gap }
      expect(diag.segment).to eq 0
    end

    it 'reports invalid percent escapes with byte offsets and owning segment' do
      pairs = [
        {'f*0*' => "utf-8''a%ZZb%2c"},
        {'f*1*' => 'x%'}
      ]
      result = described_class.decode(pairs, strict: true)
      bad = result.diagnostics.select { |d| d.code == :invalid_percent_encoding }
      expect(bad.map(&:offset)).to eq [1, 9] # %ZZ in seg0 and trailing % in seg1
      expect(bad.map(&:segment)).to eq [0, 1]
      expect(bad.first.position).to eq 0
      expect(bad.last.position).to eq 1
      expect(bad.first.raw_segments).to eq ["f*0*=utf-8''a%ZZb%2c", 'f*1*=x%']
    end

    it 'locates a bad percent escape in a later segment' do
      pairs = [
        {'f*0*' => "utf-8''abc"},
        {'f*1*' => 'd%20e%zz'}
      ]
      result = described_class.decode(pairs, strict: true)
      diag = result.diagnostics.find { |d| d.code == :invalid_percent_encoding }
      expect(diag.segment).to eq 1
      expect(diag.offset).to eq 8
    end

    it 'still best-effort decodes values that contain invalid escapes' do
      result = described_class.decode(
        [{'f*0*' => "us-ascii''a%ZZb%2c"}], strict: true
      )
      expect(result.parameters['f']).to eq 'a%ZZb,'
    end

    it 'reports unsupported charsets and keeps the charset name' do
      result = described_class.decode(
        [{'f*' => "totally-bogus-charset'en'hi"}], strict: true
      )
      diag = result.diagnostics.find { |d| d.code == :unsupported_charset }
      expect(diag.charset).to eq 'totally-bogus-charset'
      expect(diag.parameter).to eq 'f'
      expect(diag.position).to eq 0
    end

    it 'accepts recognized MIME charset aliases' do
      result = described_class.decode(
        [{'f*' => "windows-31j'jp'01%20x.mp3"}], strict: true
      )
      expect(result.diagnostics.map(&:code)).not_to include(:unsupported_charset)
    end

    it 'reports plain/extended conflicts with both raw fragments' do
      pairs = [
        {'f' => 'plain-value'},
        {'f*' => "us-ascii''extended-value"}
      ]
      result = described_class.decode(pairs, strict: true, field: 'Content-Disposition')
      diag = result.diagnostics.find { |d| d.code == :parameter_conflict }
      expect(diag.field).to eq 'Content-Disposition'
      expect(diag.parameter).to eq 'f'
      expect(diag.position).to eq 0
      expect(diag.raw_segments).to eq ['f=plain-value', "f*=us-ascii''extended-value"]
      expect(result.parameters['f']).to eq 'extended-value'
    end

    it 'reports conflicts between plain and continued extended forms' do
      pairs = [
        {'f' => 'plain'},
        {'f*0*' => "utf-8''a"},
        {'f*1*' => 'b'}
      ]
      result = described_class.decode(pairs, strict: true)
      codes = result.diagnostics.map(&:code)
      expect(codes).to include(:parameter_conflict)
      expect(codes).not_to include(:segment_gap, :duplicate_segment)
    end

    it 'gathers several independent problems at once' do
      pairs = [
        {'f*0*' => "bogus''a%"},
        {'f*0*' => 'b'},
        {'g' => 'plain'},
        {'g*' => "us-ascii''ext"}
      ]
      result = described_class.decode(pairs, strict: true)
      expect(result.diagnostics.map(&:code)).to match_array(
        [:duplicate_segment, :unsupported_charset, :invalid_percent_encoding, :parameter_conflict]
      )
    end

    it 'exposes diagnostics as structured hashes' do
      result = described_class.decode([{'f*0*' => "utf-8''a%"}], strict: true)
      hash = result.diagnostics.first.to_h
      expect(hash[:code]).to eq :invalid_percent_encoding
      expect(hash[:parameter]).to eq 'f'
      expect(hash[:position]).to eq 0
      expect(hash[:segment]).to eq 0
      expect(hash[:offset]).to eq 1
      expect(hash[:message]).to be_a(String)
    end
  end

  describe '.decode!' do
    it 'returns the parameters when valid' do
      parameters = described_class.decode!(
        [{'f*' => "us-ascii''hello%20world"}]
      )
      expect(parameters['f']).to eq 'hello world'
    end

    it 'raises Mail::ParameterError carrying the result and diagnostics' do
      begin
        described_class.decode!([{'f*' => "bogus''x%"}])
        flunk 'expected Mail::ParameterError'
      rescue Mail::ParameterError => e
        expect(e.result).not_to be_valid
        expect(e.diagnostics.map(&:code)).to match_array(
          [:unsupported_charset, :invalid_percent_encoding]
        )
        expect(e.message).to include('invalid MIME parameters')
      end
    end
  end
end

RSpec.describe Mail::ParameterHash do
  it 'exposes strict decoding of raw parser parameter pairs' do
    pairs = [{'f*0*' => "utf-8''a"}, {'f*2*' => 'b'}]
    result = Mail::ParameterHash.decode_pairs(pairs, field: 'Content-Type')
    expect(result.diagnostics.map(&:code)).to eq [:segment_gap]
    expect(result.parameters['f']).to eq 'ab'
  end

  it 'raises from decode_pairs! when diagnostics exist' do
    expect {
      Mail::ParameterHash.decode_pairs!([{'f*' => "bogus''x%"}])
    }.to raise_error(Mail::ParameterError)
  end
end

RSpec.describe 'strict RFC 2231 access from fields' do
  it 'is available on Content-Type fields' do
    field = Mail::ContentTypeField.new(
      'application/octet-stream; filename*0*=utf-8\'\'%E4%B8%AD; filename*2*=x'
    )
    result = field.decoded_parameters(strict: true)
    expect(result.diagnostics.map(&:code)).to eq [:segment_gap]
    diag = result.diagnostics.first
    expect(diag.field).to eq 'Content-Type'
    expect(diag.parameter).to eq 'filename'
    expect(diag.segment).to eq 1
    expect(result.parameters['filename']).to eq field.filename
  end

  it 'is available on Content-Disposition fields' do
    field = Mail::ContentDispositionField.new(
      "attachment; filename=plain.txt; filename*=us-ascii''ext.txt"
    )
    result = field.decoded_parameters(strict: true)
    expect(result.diagnostics.map(&:code)).to eq [:parameter_conflict]
    expect(result.diagnostics.first.raw_segments).to eq(
      ['filename=plain.txt', "filename*=us-ascii''ext.txt"]
    )
  end

  it 'defaults to the lenient hash on both field kinds' do
    field = Mail::ContentTypeField.new(
      'application/octet-stream; filename*0*=a; filename*2*=c'
    )
    expect(field.decoded_parameters['filename']).to eq field.parameters['filename']

    disposition = Mail::ContentDispositionField.new(
      "attachment; filename=ok.txt"
    )
    expect(disposition.decoded_parameters['filename']).to eq disposition.parameters['filename']
  end
end
