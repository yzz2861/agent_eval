# frozen_string_literal: true

require_relative 'test_helper'

class RangedIoTest < Minitest::Test
  class MemoryRangedSource
    attr_reader :ranges, :version_checks

    def initialize(data, version = 'version-1', short_read: false)
      @data = data.b
      @version = version
      @short_read = short_read
      @ranges = []
      @version_checks = 0
    end

    def size
      @data.bytesize
    end

    def version
      @version_checks += 1
      @version
    end

    def read_at(offset, length)
      data = @data.byteslice(offset, length)
      data = data.byteslice(0, data.bytesize - 1) if @short_read && data
      @ranges << [offset, data&.bytesize || 0]
      [data, @version]
    end
  end

  class ChangingRangedSource < MemoryRangedSource
    def read_at(offset, length)
      @version = 'version-2'
      super
    end
  end

  class SparseRangedSource
    attr_reader :ranges, :version

    def initialize(segments, version = 'version-1')
      @segments = segments
      @size = segments.last.first + segments.last.last.bytesize
      @version = version
      @ranges = []
    end

    def size
      @size
    end

    def read_at(offset, length)
      data = +''.b
      cursor = offset
      remaining_length = length

      @segments.each do |segment_offset, segment_data|
        segment_end = segment_offset + segment_data.bytesize
        gap = segment_offset - cursor
        if gap.positive? && remaining_length.positive?
          zero_length = [gap, remaining_length].min
          data << "\0".b * zero_length
          cursor += zero_length
          remaining_length -= zero_length
        end
        next if cursor >= segment_end

        chunk_offset = [cursor, segment_offset].max - segment_offset
        chunk_length = [[segment_end, cursor + remaining_length].min -
                        (segment_offset + chunk_offset), 0].max
        if chunk_length.positive?
          data << segment_data.b.byteslice(chunk_offset, chunk_length)
          cursor += chunk_length
          remaining_length -= chunk_length
        end
      end
      data << "\0".b * remaining_length if remaining_length.positive?

      @ranges << [offset, [data.bytesize, length].min]
      [data, @version]
    end
  end

  def test_open_and_read_small_entry_without_downloading_archive
    archive = build_archive
    source = MemoryRangedSource.new(archive)

    Zip::File.open(source) do |zip_file|
      assert_equal('small', zip_file.read('small.txt'))
    end

    refute_includes(source.ranges.map { |offset, length| length }, archive.bytesize)
    assert(source.ranges.sum { |_, length| length } < archive.bytesize)
    assert_merge_includes_entry(source, archive.index('small.txt'), 'small'.bytesize)
    assert_operator(source.version_checks, :>=, source.ranges.size * 2)
    assert_equal(2, source.ranges.size)
  end

  def test_reads_selected_entry_from_sparse_zip64_archive
    source = build_sparse_zip64_source

    Zip::File.open(source) do |zip_file|
      assert_equal(1, zip_file.size)
      assert_equal('small', zip_file.read('small.txt'))
    end

    assert(source.ranges.sum { |_, length| length } < 200_000)
    assert(source.ranges.any? { |offset, length| offset + length > 2**32 })
  end

  def test_reads_archive_with_maximum_eocd_comment
    archive = File.binread('test/data/max_length_file_comment.zip')
    source = MemoryRangedSource.new(archive)

    Zip::File.open(source) do |zip_file|
      assert_equal(65_535, zip_file.comment.bytesize)
      assert_equal('README.md', zip_file.entries.first.name)
    end

    assert(source.ranges.any?)
  end

  def test_rejects_short_response
    source = MemoryRangedSource.new('abcdef', short_read: true)
    io = Zip::RangedIO.new(source)

    error = assert_raises(Zip::RangedSourceShortReadError) do
      io.read(6)
    end
    assert_match(/requested 6 bytes, got 5/, error.message)
  end

  def test_rejects_read_outside_data_source
    io = Zip::RangedIO.new(MemoryRangedSource.new('abcdef'))
    io.seek(6)

    assert_nil(io.read(1))
  end

  def test_input_stream_reads_ranged_source_directly
    archive = build_archive
    source = MemoryRangedSource.new(archive)
    offset = archive.index('small.txt') - 30

    Zip::InputStream.open(source, offset: offset) do |stream|
      assert_equal('small.txt', stream.get_next_entry.name)
      assert_equal('small', stream.read)
    end
  end

  def test_rejects_data_from_a_different_version
    io = Zip::RangedIO.new(ChangingRangedSource.new('abcdef'))

    error = assert_raises(Zip::RangedSourceVersionError) do
      io.read(6)
    end
    assert_equal('version-1', error.expected_version)
    assert_equal('version-2', error.actual_version)
  end

  def test_rejects_corrupt_central_directory_offset
    archive = build_archive
    archive[archive.bytesize - 6, 4] = [archive.bytesize].pack('V')
    source = MemoryRangedSource.new(archive)

    assert_raises(Zip::Error) do
      Zip::File.open(source)
    end
  end

  def test_rejects_corrupt_local_header_offset
    archive = build_archive
    small_record_offset = archive.rindex('small.txt') - 46
    archive[small_record_offset + 42, 4] = [archive.bytesize].pack('V')
    source = MemoryRangedSource.new(archive)

    Zip::File.open(source) do |zip_file|
      assert_raises(Zip::Error) do
        zip_file.read('small.txt')
      end
    end
  end

  def test_propagates_short_response_while_reading_entries
    source = MemoryRangedSource.new(build_archive, 'version-1', short_read: true)

    assert_raises(Zip::RangedSourceShortReadError) do
      Zip::File.open(source)
    end
  end

  private

  def build_archive
    Zip::OutputStream.write_buffer(StringIO.new) do |zip|
      zip.put_next_entry('filler.bin', '', Zip::ExtraField.new,
                         Zip::Entry::STORED, 0)
      zip.write('x' * 140_000)
      zip.put_next_entry('small.txt', '', Zip::ExtraField.new,
                         Zip::Entry::STORED, 0)
      zip.write('small')
      zip.put_next_entry('tail.bin', '', Zip::ExtraField.new,
                         Zip::Entry::STORED, 0)
      zip.write('y' * 70_000)
    end.string
  end

  def build_sparse_zip64_source
    content = 'small'
    entry = Zip::Entry.new(
      nil, 'small.txt', size: content.bytesize, compressed_size: content.bytesize,
      crc: Zlib.crc32(content), compression_method: Zip::Entry::STORED,
      compression_level: 0
    )

    local_io = StringIO.new
    entry.send(:write_local_entry, local_io)
    local_io.write(content)
    local_data = local_io.string

    base_offset = 2**32
    entry.local_header_offset = base_offset
    central_io = StringIO.new
    entry.send(:write_c_dir_entry, central_io)
    central_data = central_io.string

    central_offset = base_offset + 50_000
    zip64_eocd_offset = central_offset + central_data.bytesize
    zip64_eocd = [
      0x06064b50, 44, 52, 45, 0, 0, 1, 1,
      central_data.bytesize, central_offset
    ].pack('VQ<vvVVQ<Q<Q<Q<')
    locator = [0x07064b50, 0, zip64_eocd_offset, 1].pack('VVQ<V')
    eocd = [0x06054b50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0].pack('VvvvvVVv')

    SparseRangedSource.new([
      [base_offset, local_data],
      [central_offset, central_data],
      [zip64_eocd_offset, zip64_eocd + locator + eocd]
    ])
  end

  def assert_merge_includes_entry(source, entry_offset, content_size)
    header_size = 30 + 'small.txt'.bytesize
    merged_range = source.ranges.find do |offset, length|
      offset <= entry_offset && offset + length >= entry_offset + header_size + content_size
    end

    assert(merged_range, "expected merged range around #{entry_offset}")
  end
end
