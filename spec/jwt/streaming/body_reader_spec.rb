# frozen_string_literal: true

RSpec.describe JWT::Streaming::BodyReader do
  it 'requires a readable source' do
    expect { described_class.new(:nope, chunk_size: 1) }.to raise_error(ArgumentError, /#read/)
  end

  it 'requires a positive integer chunk size' do
    io = StringIO.new('abc')
    expect { described_class.new(io, chunk_size: 0) }.to raise_error(ArgumentError, /chunk_size/)
    expect { described_class.new(io, chunk_size: 1.5) }.to raise_error(ArgumentError, /chunk_size/)
  end

  it 'yields chunks and records statistics' do
    io = StringIO.new('abcdefghij')
    stats = JWT::Streaming::Stats.new
    chunks = []
    described_class.new(io, chunk_size: 4, stats: stats).each { |chunk| chunks << chunk }
    expect(chunks).to eq(%w[abcd efgh ij])
    expect(stats.reads).to eq(3)
    expect(stats.bytes_read).to eq(10)
    expect(stats.max_read_length).to eq(4)
  end

  it 'reads nothing from an empty source' do
    stats = JWT::Streaming::Stats.new
    pieces = []
    described_class.new(StringIO.new(''), chunk_size: 4, stats: stats).each { |chunk| pieces << chunk }
    expect(pieces).to eq([])
    expect(stats.reads).to eq(0)
  end
end
