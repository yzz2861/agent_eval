# frozen_string_literal: true

require_relative 'test_helper'

# An IO that only exposes what a forward-only destination provides: write
# (and binmode). It never seeks or reports a position, and it can be made to
# return fewer bytes than requested so the writer's short-write handling is
# exercised.
class WriteOnlySink
  def initialize(short_writes: 0)
    @buffer = +''.b
    @short_writes = short_writes
    @write_calls = 0
  end

  attr_reader :buffer, :write_calls

  def binmode
    @binmode = true
  end

  def binmode?
    @binmode == true
  end

  def write(data)
    data = data.to_s
    @write_calls += 1
    # Mimic a blocking IO: usually accept everything; occasionally accept
    # just one byte so the caller has to keep retrying until it is done.
    if @short_writes.positive? && data.bytesize > 1
      @short_writes -= 1
      @buffer << data.byteslice(0, 1)
      return 1
    end
    @buffer << data
    data.bytesize
  end

  def to_s
    @buffer
  end
end

class ZipForwardOutputStreamTest < Minitest::Test
  STORED_CONTENT = "store me, pipe!"
  DEFLATED_CONTENT = "deflate me to a pipe! " * 200

  def teardown
    ::Zip.reset!
  end

  def test_writes_deflated_and_stored_entries_to_a_write_only_io
    sink = WriteOnlySink.new

    ::Zip::OutputStream.write_stream(sink, comment: 'streamed') do |zos|
      zos.put_next_entry('stored.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      zos.write(STORED_CONTENT)
      zos.put_next_entry('deflated.txt')
      zos << DEFLATED_CONTENT
      zos.put_next_entry('empty.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      zos.put_next_entry('a/dir/')
    end

    assert sink.binmode?
    verify_archive(sink.buffer, comment: 'streamed',
                   names: %w[stored.txt deflated.txt empty.txt a/dir/],
                   stored_name: 'stored.txt', deflated_name: 'deflated.txt')
  end

  def test_handles_repeated_short_writes
    sink = WriteOnlySink.new(short_writes: 6)

    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('stored.bin', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      zos.write(STORED_CONTENT)
      zos.put_next_entry('deflated.bin')
      zos.write(DEFLATED_CONTENT)
    end

    # Every short write forces an extra write call for the remainder.
    assert_operator sink.write_calls, :>, 6
    verify_archive(sink.buffer, comment: '',
                   names: %w[stored.bin deflated.bin],
                   stored_name: 'stored.bin', deflated_name: 'deflated.bin')
  end

  def test_direct_use_finishes_and_flushes_without_closing_target
    sink = WriteOnlySink.new
    zos = ::Zip::ForwardOutputStream.new(sink, comment: 'c')
    zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new, ::Zip::Entry::STORED)
    zos.write('hello')
    zos.finish

    assert zos.closed?
    ::Zip::File.open_buffer(sink.buffer) do |zf|
      assert_equal 'hello', zf.read('a.txt')
      assert_equal 'c', zf.comment
    end
  end

  def test_close_is_idempotent_and_writes_the_central_directory_once
    sink = WriteOnlySink.new
    zos = ::Zip::ForwardOutputStream.new(sink)
    zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new, ::Zip::Entry::STORED)
    zos.write('a')
    zos.close
    first_size = sink.buffer.bytesize
    zos.close

    assert_equal first_size, sink.buffer.bytesize
    assert_equal 1, sink.buffer.scan([::Zip::CentralDirectory::END_OF_CD_SIG].pack('V')).length
  end

  def test_empty_archive_is_valid
    sink = WriteOnlySink.new
    zos = ::Zip::OutputStream.write_stream(sink)
    zos.finish

    assert_valid_empty_eocd(sink.buffer)
  end

  def test_entries_carry_data_descriptor_flags
    sink = WriteOnlySink.new
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new, ::Zip::Entry::STORED)
      zos.write('abc')
    end

    # Local file header with bit 3 set and a data descriptor signature.
    assert_equal [0x04034b50].pack('V'), sink.buffer.byteslice(0, 4)
    gp_flags = sink.buffer.byteslice(6, 2).unpack1('v')
    assert_equal 0b1000, gp_flags & 0b1000
    assert_includes sink.buffer, [0x08074b50].pack('V')
  end

  def test_zip64_mode_is_declared_up_front_and_round_trips
    sink = WriteOnlySink.new

    ::Zip::OutputStream.write_stream(sink, zip64: true, comment: 'streamed') do |zos|
      zos.put_next_entry('stored.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
      zos.write(STORED_CONTENT)
      zos.put_next_entry('deflated.txt')
      zos.write(DEFLATED_CONTENT)
    end

    assert_includes sink.buffer,
                    [::Zip::CentralDirectory::ZIP64_END_OF_CD_SIG].pack('V')
    verify_archive(sink.buffer, comment: 'streamed',
                   names: %w[stored.txt deflated.txt],
                   stored_name: 'stored.txt', deflated_name: 'deflated.txt')

    ::Zip::File.open_buffer(sink.buffer) do |zf|
      zf.each do |entry|
        assert entry.zip64?
        assert_equal ::Zip::VERSION_NEEDED_TO_EXTRACT_ZIP64,
                     entry.version_needed_to_extract
      end
    end
  end

  def test_classic_mode_raises_when_a_size_would_overflow
    error = ::Zip::Zip64RequiredError.new(0x1_0000_0000, 'uncompressed size')
    assert_match(/zip64/i, error.message)
    assert_match(/uncompressed size/, error.message)

    zos = ::Zip::ForwardOutputStream.new(WriteOnlySink.new)
    assert_raises(::Zip::Zip64RequiredError) do
      zos.send(:check_32bit_limit, 0x1_0000_0000, 0xFFFFFFFF, 'x')
    end
  end

  def test_classic_mode_raises_up_front_when_header_offset_overflows
    sink = WriteOnlySink.new
    zos = ::Zip::ForwardOutputStream.new(sink)
    zos.instance_variable_get(:@io).instance_variable_set(:@bytes_written,
                                                           0xFFFFFFFF)

    error = assert_raises(::Zip::Zip64RequiredError) do
      zos.put_next_entry('late.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
    end
    assert_match(/local header offset/, error.message)
    # Nothing should have been emitted for the refused entry.
    refute_includes sink.buffer, 'late.txt'
  end

  def test_writing_after_close_raises
    zos = ::Zip::ForwardOutputStream.new(WriteOnlySink.new)
    zos.close
    assert_raises(IOError) { zos.write('x') }
    assert_raises(IOError) { zos << 'x' }
  end

  def test_exception_in_block_does_not_fabricate_a_central_directory
    sink = WriteOnlySink.new
    error = assert_raises(RuntimeError) do
      ::Zip::OutputStream.write_stream(sink) do |zos|
        zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new,
                           ::Zip::Entry::STORED)
        zos.write('abc')
        raise 'writer exploded'
      end
    end

    assert_equal 'writer exploded', error.message
    refute_includes sink.buffer,
                    [::Zip::CentralDirectory::END_OF_CD_SIG].pack('V')
    refutable_zip(sink.buffer)
  end

  def test_abort_leaves_a_partial_stream_that_cannot_be_completed
    sink = WriteOnlySink.new
    zos = ::Zip::ForwardOutputStream.new(sink)
    zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new, ::Zip::Entry::STORED)
    zos.write('abc')
    zos.abort

    refute_includes sink.buffer,
                    [::Zip::CentralDirectory::END_OF_CD_SIG].pack('V')
    assert_raises(IOError) { zos.put_next_entry('b.txt') }
    zos.close # must stay a no-op, not append a central directory
    refute_includes sink.buffer,
                    [::Zip::CentralDirectory::END_OF_CD_SIG].pack('V')
  end

  def test_underlying_write_error_is_propagated
    sink = Object.new
    def sink.binmode; end
    def sink.write(_data)
      raise Errno::EPIPE, 'broken pipe'
    end

    zos = ::Zip::ForwardOutputStream.new(sink)
    assert_raises(SystemCallError) do
      zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
    end
  end

  def test_duplicate_names_are_rejected
    sink = WriteOnlySink.new
    zos = ::Zip::ForwardOutputStream.new(sink)
    zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new, ::Zip::Entry::STORED)
    zos.write('a')
    assert_raises(::Zip::EntryExistsError) do
      zos.put_next_entry('a.txt', '', ::Zip::ExtraField.new,
                         ::Zip::Entry::STORED)
    end
  end

  def test_entry_objects_can_be_passed_in
    sink = WriteOnlySink.new
    entry = ::Zip::Entry.new(nil, 'custom.txt', comment: 'n',
                             compression_method: ::Zip::Entry::STORED)
    ::Zip::OutputStream.write_stream(sink) do |zos|
      zos.put_next_entry(entry)
      zos.write('custom content')
    end

    ::Zip::File.open_buffer(sink.buffer) do |zf|
      assert_equal 'custom content', zf.read('custom.txt')
      assert_equal 'n', zf.get_entry('custom.txt').comment
    end
  end

  private

  def verify_archive(bytes, comment:, names:, stored_name:, deflated_name:)
    ::Zip::File.open_buffer(StringIO.new(bytes)) do |zf|
      assert_equal names, zf.entries.map(&:name)
      assert_equal comment, zf.comment

      stored = zf.get_entry(stored_name)
      deflated = zf.get_entry(deflated_name)
      assert_equal ::Zip::Entry::STORED, stored.compression_method
      assert_equal ::Zip::Entry::DEFLATED, deflated.compression_method
      assert_equal STORED_CONTENT.bytesize, stored.size
      assert_equal STORED_CONTENT.bytesize, stored.compressed_size
      assert_equal DEFLATED_CONTENT.bytesize, deflated.size
      if names.include?('empty.txt')
        assert_equal 0, zf.get_entry('empty.txt').size
      end
      if names.include?('a/dir/')
        assert zf.get_entry('a/dir/').directory?
      end
      assert_equal Zlib.crc32(STORED_CONTENT), stored.crc
      assert_equal Zlib.crc32(DEFLATED_CONTENT), deflated.crc
      assert_equal STORED_CONTENT, zf.read(stored_name)
      assert_equal DEFLATED_CONTENT, zf.read(deflated_name)
      assert_equal '', zf.read('empty.txt') if names.include?('empty.txt')
    end
  end

  def refutable_zip(bytes)
    assert_raises(::Zip::Error) do
      ::Zip::File.open_buffer(StringIO.new(bytes)) { |zf| zf.entries }
    end
  end

  def assert_valid_empty_eocd(bytes)
    assert_equal 22, bytes.bytesize
    sig, _disk, _cdir_disk, _entries_disk, entries_total, cdir_size,
      cdir_offset, comment_length = bytes.unpack('VvvvvVVv')
    assert_equal ::Zip::CentralDirectory::END_OF_CD_SIG, sig
    assert_equal 0, entries_total
    assert_equal 0, cdir_size
    assert_equal 0, cdir_offset
    assert_equal 0, comment_length
  end
end
