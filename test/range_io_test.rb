# frozen_string_literal: true

require_relative 'test_helper'

# An in-memory `read_at` data source that records every requested byte
# range, used to prove exactly which parts of an archive are fetched.
class RecordingSource
  attr_reader :reads
  attr_accessor :version

  def initialize(data, version: 'v1', max_chunk: nil)
    @data = data.b
    @version = version
    @max_chunk = max_chunk
    @reads = []
  end

  def read_at(offset, length)
    @reads << [offset, length]
    length = [length, @max_chunk].min if @max_chunk
    @data.byteslice(offset, length) || +''.b
  end

  def size
    @data.bytesize
  end

  def total_bytes_read
    @reads.sum { |(_, length)| length }
  end
end

# A source that doesn't report its size, to exercise size probing.
class SizelessSource < RecordingSource
  undef size
end

# A source that changes its version during a read.
class FlippingSource < RecordingSource
  def read_at(offset, length)
    @version = 'v2'
    super
  end
end

class RangeIOTest < Minitest::Test
  DATA = 'abcdefghijklmnopqrstuvwxyz'

  def new_io(source = RecordingSource.new(DATA), **opts)
    ::Zip::RangeIO.new(source, **opts)
  end

  def test_requires_the_source_protocol
    assert_raises(ArgumentError) { ::Zip::RangeIO.new(Object.new) }
    assert_raises(ArgumentError) { ::Zip::RangeIO.new(RecordingSource.new('').tap { |s| s.singleton_class.undef_method(:version) }) }
  end

  def test_read_and_seek
    io = new_io
    assert_equal 'abc', io.read(3)
    assert_equal 3, io.tell

    io.seek(10)
    assert_equal 10, io.pos
    assert_equal 'klm', io.read(3)

    io.seek(-3, IO::SEEK_CUR)
    assert_equal 'klm', io.read(3)

    io.seek(-4, IO::SEEK_END)
    assert_equal 'wxyz', io.read(4)

    io.rewind
    assert_equal 0, io.tell
    assert_equal 'abc', io.read(3)

    io.pos = 1
    assert_equal 'bcd', io.read(3)
  end

  def test_read_to_end_of_source
    io = new_io
    io.seek(24)
    assert_equal 'yz', io.read
    assert io.eof?
    assert_equal '', io.read
  end

  def test_read_at_eof_returns_nil
    io = new_io
    io.seek(DATA.bytesize)
    assert_nil io.read(1)
    assert_equal '', io.read(0)
  end

  def test_read_past_end_is_clamped
    source = RecordingSource.new(DATA)
    io = new_io(source)
    io.seek(20)
    assert_equal 'uvwxyz', io.read(100)
    assert(source.reads.all? { |(offset, length)| offset + length <= DATA.bytesize })
  end

  def test_seek_beyond_end_is_allowed
    io = new_io
    io.seek(1000)
    assert_equal 1000, io.tell
    assert io.eof?
    assert_nil io.read(1)
  end

  def test_seek_to_negative_position_raises_einval
    io = new_io
    assert_raises(Errno::EINVAL) { io.seek(-1) }
    assert_raises(Errno::EINVAL) { io.seek(-DATA.bytesize - 1, IO::SEEK_END) }
  end

  def test_read_with_negative_length_raises
    assert_raises(ArgumentError) { new_io.read(-1) }
  end

  def test_read_with_outbuf
    io = new_io
    buf = +'old'
    assert_same buf, io.read(3, buf)
    assert_equal 'abc', buf

    io.seek(DATA.bytesize)
    assert_nil io.read(3, buf)
    assert_equal '', buf
  end

  def test_short_responses_are_retried_until_filled
    source = RecordingSource.new(DATA, max_chunk: 3)
    io = new_io(source)
    assert_equal 'abcdefghij', io.read(10)
    assert_operator source.reads.length, :>, 1
    assert_equal [[0, 26], [3, 23], [6, 20], [9, 17], [12, 14], [15, 11], [18, 8], [21, 5], [24, 2]], source.reads
  end

  def test_empty_response_is_treated_as_end_of_data
    source = RecordingSource.new(DATA)
    def source.read_at(*) = +''.b
    assert_equal '', new_io(source).read(5)
  end

  def test_adjacent_small_reads_are_merged
    source = RecordingSource.new(DATA * 100)
    io = new_io(source, buffer_size: 128)
    assert_equal 'abcd', io.read(4)
    assert_equal 'efgh', io.read(4)
    io.seek(100)
    assert_equal 'wxyz', io.read(4)
    assert_equal 1, source.reads.length
    assert_equal [0, 128], source.reads.first
  end

  def test_distant_read_refills_the_buffer
    source = RecordingSource.new(DATA * 100)
    io = new_io(source, buffer_size: 128)
    io.read(4)
    io.seek(1000)
    io.read(4)
    assert_equal [[0, 128], [1000, 128]], source.reads
  end

  def test_large_reads_bypass_the_buffer
    source = RecordingSource.new(DATA * 100)
    io = new_io(source, buffer_size: 128)
    assert_equal 200, io.read(200).bytesize
    assert_equal [[0, 200]], source.reads
  end

  def test_size_is_discovered_by_probing_when_not_reported
    source = SizelessSource.new(DATA * 100)
    io = new_io(source, buffer_size: 64)
    assert_equal 2600, io.size
    io.seek(-4, IO::SEEK_END)
    assert_equal 'wxyz', io.read(4)
  end

  def test_probe_handles_empty_source
    assert_equal 0, new_io(SizelessSource.new('')).size
  end

  def test_version_change_between_reads_raises
    source = RecordingSource.new(DATA)
    io = new_io(source)
    io.read(4)
    source.version = 'v2'
    assert_raises(::Zip::SourceVersionError) { io.read(4) }
  end

  def test_version_change_during_a_read_raises
    assert_raises(::Zip::SourceVersionError) { new_io(FlippingSource.new(DATA)).read(4) }
  end

  def test_closed_io_raises
    io = new_io
    io.close
    assert io.closed?
    assert_raises(IOError) { io.read(1) }
    assert_raises(IOError) { io.seek(0) }
  end

  def test_dup_has_an_independent_position
    io = new_io
    io.seek(10)
    copy = io.dup
    copy.seek(0)
    copy.read(5)
    assert_equal 10, io.tell
  end
end

class RangeIOSourceIntegrationTest < Minitest::Test
  ZIP64_TEST_FILE = File.join(File.dirname(__FILE__), 'data', 'zip64-sample.zip')

  def build_archive(entries, comment: '')
    ::Zip::OutputStream.write_buffer do |zos|
      entries.each do |name, data|
        zos.put_next_entry(name)
        zos.write(data)
      end
      zos.comment = comment
    end.string
  end

  def test_open_and_read_entries_from_a_source
    archive = build_archive({ 'a.txt' => 'aaa', 'dir/b.txt' => 'bbb' })
    zip = ::Zip::File.new(RecordingSource.new(archive))

    assert_equal %w[a.txt dir/b.txt], zip.entries.map(&:name)
    assert_equal 'aaa', zip.read('a.txt')
    assert_equal 'bbb', zip.read('dir/b.txt')
    assert_equal 2, ::Zip::File.count_entries(RecordingSource.new(archive))
  end

  def test_open_with_block_and_close
    archive = build_archive({ 'a.txt' => 'aaa' })
    ::Zip::File.open(RecordingSource.new(archive)) do |zip|
      assert_equal 'aaa', zip.read('a.txt')
    end
  end

  def test_reading_a_small_entry_does_not_download_the_whole_archive
    big_data = Random.new(42).bytes(2_000_000)
    archive = build_archive({ 'big.bin' => big_data, 'small.txt' => 'hello world' })
    source = RecordingSource.new(archive)

    zip = ::Zip::File.new(source)
    assert_equal %w[big.bin small.txt], zip.entries.map(&:name)

    source.reads.clear
    assert_equal 'hello world', zip.read('small.txt')

    fetched = source.total_bytes_read
    assert fetched < archive.bytesize / 4,
           "expected only a small part of the archive to be fetched, but fetched #{fetched} of #{archive.bytesize} bytes"
    assert(source.reads.none? { |(_, length)| length >= big_data.bytesize })
  end

  def test_archive_with_maximum_length_comment
    comment = 'x' * 65_535
    archive = build_archive({ 'a.txt' => 'data' }, comment: comment)
    zip = ::Zip::File.new(RecordingSource.new(archive))

    assert_equal comment, zip.comment
    assert_equal 'data', zip.read('a.txt')
  end

  def test_zip64_archive
    source = RecordingSource.new(::File.binread(ZIP64_TEST_FILE))
    zip = ::Zip::File.new(source)

    assert_equal 2, zip.entries.count
    test_rb = zip.entries.find { |entry| entry.name == 'test.rb' }
    assert_equal 482, test_rb.size
    assert_equal 482, zip.read('test.rb').bytesize
  end

  def test_short_responses_from_the_source
    archive = build_archive({ 'a.txt' => 'a' * 1000, 'b.txt' => 'b' * 1000 })
    source = RecordingSource.new(archive, max_chunk: 100)
    zip = ::Zip::File.new(source)

    assert_equal 'a' * 1000, zip.read('a.txt')
    assert_equal 'b' * 1000, zip.read('b.txt')
  end

  def test_version_change_while_reading_entries_raises
    archive = build_archive({ 'a.txt' => 'aaa', 'b.txt' => 'bbb' })
    source = RecordingSource.new(archive)
    zip = ::Zip::File.new(source)
    assert_equal 'aaa', zip.read('a.txt')

    source.version = 'v2'
    assert_raises(::Zip::SourceVersionError) { zip.read('b.txt') }
  end

  def test_version_change_during_open_raises
    archive = build_archive({ 'a.txt' => 'aaa' })
    assert_raises(::Zip::SourceVersionError) { ::Zip::File.new(FlippingSource.new(archive)) }
  end
end
