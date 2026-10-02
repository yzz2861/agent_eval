# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/decompressor_tests'

class InflaterTest < Minitest::Test
  include DecompressorTests

  # The maximum expansion ratio of the deflate algorithm is a little over
  # 1000:1 (1032:1), so this is the most that inflating one input chunk can
  # ever add to the buffer.
  MAX_DEFLATE_RATIO = 1032
  READ_LENGTH = 16_384

  def setup
    super
    @file = File.new('test/data/file1.txt.deflatedData', 'rb')
    @decompressor = ::Zip::Inflater.new(@file)
  end

  def teardown
    @file.close
    ::Zip.reset!
  end

  def test_default_inflater_chunk_size
    assert_equal(4096, Zip.inflater_chunk_size)
  end

  def test_buffer_is_bounded_when_reading_highly_compressible_data
    # 8 MiB of repeated XML deflates to under 32 KiB. With a 32 KiB input
    # chunk a single read inflates the whole entry into the buffer; with the
    # default 4 KiB chunk the buffer is bounded by what one chunk can inflate to.
    data, compressed = highly_compressible_data
    bound = Zip.inflater_chunk_size * MAX_DEFLATE_RATIO

    output, peak = read_in_chunks(compressed, bound)

    assert_equal(data, output)
    assert_operator(peak, :<=, bound + READ_LENGTH)
    assert_operator(peak, :<, data.bytesize / 2)
  end

  def test_inflater_chunk_size_is_configurable
    data, compressed = highly_compressible_data
    Zip.inflater_chunk_size = Zip::Decompressor::CHUNK_SIZE

    output, peak = read_in_chunks(compressed)

    assert_equal(data, output)
    # The whole entry is inflated on the first read.
    assert_operator(peak, :>=, data.bytesize)
  end

  private

  def highly_compressible_data
    row = '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><v>12345</v></c></row>'
    data = (row * ((8 * 1024 * 1024 / row.bytesize) + 1)).b
    deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
    compressed = deflater.deflate(data, Zlib::FINISH)
    deflater.close
    assert_operator(compressed.bytesize, :<, Zip::Decompressor::CHUNK_SIZE)

    [data, compressed]
  end

  # Reads all of `compressed` in READ_LENGTH chunks. Returns the inflated data
  # and the peak size of the inflater's buffer, checking after each read that
  # what is left in the buffer is within `bound` if one is given.
  def read_in_chunks(compressed, bound = nil)
    inflater = Zip::Inflater.new(StringIO.new(compressed))
    output = +''.b
    peak = 0
    while (chunk = inflater.read(READ_LENGTH))
      output << chunk
      # The buffer has just had `chunk` sliced off it, so this is the excess
      # inflated beyond what the caller asked for.
      remaining = inflater.instance_variable_get(:@buffer).bytesize
      peak = [peak, remaining + chunk.bytesize].max
      assert_operator(remaining, :<=, bound) if bound
    end

    [output, peak]
  end
end
