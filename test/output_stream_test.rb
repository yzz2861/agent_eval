# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'helpers/assert_entry'

class ZipOutputStreamTest < Minitest::Test
  include AssertEntry

  TEST_ZIP = TestZipFile::TEST_ZIP2.clone
  TEST_ZIP.zip_name = 'test/data/generated/output.zip'

  class WriteOnlyIO
    attr_reader :string

    def initialize(limit: nil)
      @string = +''.b
      @limit = limit
    end

    def write(data)
      data = data.to_s.b
      raise IOError, 'broken pipe' if @fail_on_content

      amount = @limit ? [data.bytesize, @limit].min : data.bytesize
      @string << data.byteslice(0, amount)
      amount
    end
  end

  class FailContentIO < WriteOnlyIO
    def write(data)
      raise IOError, 'broken pipe' if data.to_s == 'content'

      super
    end
  end

  def teardown
    ::Zip.reset!
  end

  def test_new
    zos = ::Zip::OutputStream.new(TEST_ZIP.zip_name)

    assert_equal(Encoding::ASCII_8BIT, zos.external_encoding)
    assert_nil(zos.internal_encoding)

    zos.comment = TEST_ZIP.comment
    write_test_zip(zos)
    zos.close
    assert_test_zip_contents(TEST_ZIP)
  end

  def test_open
    ::Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      assert_equal(Encoding::ASCII_8BIT, zos.external_encoding)
      assert_nil(zos.internal_encoding)

      zos.comment = TEST_ZIP.comment
      write_test_zip(zos)
    end
    assert_test_zip_contents(TEST_ZIP)
  end

  def test_open_without_block_forwards_options
    encrypter = ::Zip::TraditionalEncrypter.new('password')
    zos = ::Zip::OutputStream.open(
      TEST_ZIP.zip_name,
      encrypter:             encrypter,
      suppress_extra_fields: true
    )

    assert_same encrypter, zos.instance_variable_get(:@encrypter)
    assert_equal true, zos.instance_variable_get(:@suppress_extra_fields)
  ensure
    zos&.close
  end

  def test_write_buffer
    buffer = ::Zip::OutputStream.write_buffer(::StringIO.new) do |zos|
      assert_equal(Encoding::ASCII_8BIT, zos.external_encoding)
      assert_nil(zos.internal_encoding)

      zos.comment = TEST_ZIP.comment
      write_test_zip(zos)
    end
    File.binwrite(TEST_ZIP.zip_name, buffer.string)
    assert_test_zip_contents(TEST_ZIP)
  end

  def test_write_buffer_binmode
    buffer = ::Zip::OutputStream.write_buffer(::StringIO.new) do |zos|
      assert_equal(Encoding::ASCII_8BIT, zos.external_encoding)
      assert_nil(zos.internal_encoding)

      zos.comment = TEST_ZIP.comment
      write_test_zip(zos)
    end
    assert_equal Encoding::ASCII_8BIT, buffer.external_encoding
  end

  def test_write_buffer_with_temp_file
    tmp_file = Tempfile.new('')

    ::Zip::OutputStream.write_buffer(tmp_file) do |zos|
      zos.comment = TEST_ZIP.comment
      write_test_zip(zos)
    end

    tmp_file.rewind
    File.binwrite(TEST_ZIP.zip_name, tmp_file.read)
    tmp_file.unlink

    assert_test_zip_contents(TEST_ZIP)
  end

  def test_write_buffer_with_temp_file2
    tmp_file = ::File.join(Dir.tmpdir, 'zos.zip')
    ::File.open(tmp_file, 'wb') do |f|
      ::Zip::OutputStream.write_buffer(f) do |zos|
        zos.comment = TEST_ZIP.comment
        write_test_zip(zos)
      end
    end

    ::Zip::File.open(tmp_file) # Should open without error.
  ensure
    ::File.unlink(tmp_file)
  end

  def test_write_buffer_with_default_io
    buffer = ::Zip::OutputStream.write_buffer do |zos|
      zos.comment = TEST_ZIP.comment
      write_test_zip(zos)
    end
    File.binwrite(TEST_ZIP.zip_name, buffer.string)
    assert_test_zip_contents(TEST_ZIP)
  end

  def test_writing_to_closed_stream
    assert_i_o_error_in_closed_stream { |zos| zos << 'hello world' }
    assert_i_o_error_in_closed_stream { |zos| zos.puts 'hello world' }
    assert_i_o_error_in_closed_stream { |zos| zos.write 'hello world' }
  end

  def test_cannot_open_file
    name = TestFiles::EMPTY_TEST_DIR
    begin
      ::Zip::OutputStream.open(name)
    rescue SystemCallError
      assert($ERROR_INFO.kind_of?(Errno::EISDIR) || # Linux
                 $ERROR_INFO.kind_of?(Errno::EEXIST) || # Windows/cygwin
                 $ERROR_INFO.kind_of?(Errno::EACCES), # Windows
             "Expected Errno::EISDIR (or on win/cygwin: Errno::EEXIST), but was: #{$ERROR_INFO.class}")
    end
  end

  def test_put_next_entry
    stored_text = 'hello world in stored text'
    entry_name = 'file1'
    comment = 'my comment'
    ::Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.put_next_entry(entry_name, comment, nil, ::Zip::Entry::STORED)
      zos << stored_text
    end

    assert(File.read(TEST_ZIP.zip_name, mode: 'rb')[stored_text])
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(stored_text, zf.read(entry_name))
    end
  end

  def test_put_next_entry_using_zip_entry_creates_entries_with_correct_timestamps
    file = ::File.open('test/data/file2.txt', 'rb')
    ::Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zip_entry = ::Zip::Entry.new(
        zos, file.path, time: ::Zip::DOSTime.at(file.mtime)
      )
      zos.put_next_entry(zip_entry)
      zos << file.read
    end

    ::Zip::InputStream.open(TEST_ZIP.zip_name) do |io|
      while (entry = io.get_next_entry)
        # Compare DOS Times, since they are stored with two seconds accuracy
        assert(::Zip::DOSTime.at(file.mtime) == ::Zip::DOSTime.at(entry.mtime))
      end
    end
  end

  def test_put_next_entry_raises_on_duplicate_name
    Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.put_next_entry('dup.txt')
      zos << 'first content'

      error = assert_raises(Zip::EntryExistsError) do
        zos.put_next_entry('dup.txt')
      end
      assert_match(/'put_next_entry'/, error.message)
    end

    # The first entry's data and central directory record remain intact -
    # this is the rubyzip/rubyzip#562 regression.
    Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(1, zf.size)
      assert_equal('first content', zf.read('dup.txt'))
    end
  end

  def test_put_next_entry_allows_duplicate_name_when_configured
    Zip.allow_duplicate_entry_names = true

    Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.put_next_entry('dup.txt')
      zos << 'first content'
      zos.put_next_entry('dup.txt')
      zos << 'second content'
    end

    Zip::File.open(TEST_ZIP.zip_name) do |zf|
      matches = zf.find_entry('dup.txt')
      assert_equal(2, matches.size)
      assert_equal(['first content', 'second content'],
                   matches.map { |e| zf.get_input_stream(e, &:read) })
    end
  end

  def test_copy_raw_entry_raises_on_duplicate_name
    entry = Zip::File.open(TestZipFile::TEST_ZIP2.zip_name, &:entries).first

    Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.copy_raw_entry(entry)

      error = assert_raises(Zip::EntryExistsError) do
        zos.copy_raw_entry(entry)
      end
      assert_match(/'copy_raw_entry'/, error.message)
    end

    Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(1, zf.size)
    end
  end

  def test_copy_raw_entry_allows_duplicate_name_when_configured
    entry = Zip::File.open(TestZipFile::TEST_ZIP2.zip_name, &:entries).first

    Zip.allow_duplicate_entry_names = true
    Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.copy_raw_entry(entry)
      zos.copy_raw_entry(entry)
    end

    Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(2, zf.find_entry(entry.name).size)
    end
  end

  def test_chained_put_into_next_entry
    stored_text = 'hello world in stored text'
    stored_text2 = 'with chain'
    entry_name = 'file1'
    comment = 'my comment'
    ::Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.put_next_entry(entry_name, comment, nil, ::Zip::Entry::STORED)
      zos << stored_text << stored_text2
    end

    assert(File.read(TEST_ZIP.zip_name)[stored_text])
    ::Zip::File.open(TEST_ZIP.zip_name) do |zf|
      assert_equal(stored_text + stored_text2, zf.read(entry_name))
    end
  end

  def test_print_deflated
    buffer = Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry('print_test')
      output = zos.print 'hello,', ' world'
      assert_nil(output)
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('print_test', entry.name)
      assert_equal('hello, world', zis.read)
    end
  end

  def test_printf_deflated
    buffer = Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry('printf_test')
      output = zos.printf('hello, %s', 'world')
      assert_nil(output)
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('printf_test', entry.name)
      assert_equal('hello, world', zis.read)
    end
  end

  def test_write_deflated
    buffer = Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry('write_test')
      output = zos.write 'hello, world'
      assert_equal(12, output)
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert_equal('hello, world', zis.read)
    end
  end

  def test_forward_only_writes_deflated_and_stored_entries
    io = WriteOnlyIO.new
    refute_respond_to(io, :<<)
    refute_respond_to(io, :tell)
    refute_respond_to(io, :seek)
    stored_content = 'hello from a stored entry'
    deflated_content = 'hello from a deflated entry' * 20

    ::Zip::OutputStream.write_stream(io) do |zos|
      zos.put_next_entry('stored.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
      zos.write(stored_content)

      zos.put_next_entry('deflated.txt')
      zos.write(deflated_content)
    end

    ::Zip::File.open_buffer(StringIO.new(io.string)) do |zip_file|
      entries = zip_file.entries

      assert_equal(%w[stored.txt deflated.txt], entries.map(&:name))
      assert_equal(stored_content, zip_file.read('stored.txt'))
      assert_equal(deflated_content, zip_file.read('deflated.txt'))

      stored_entry, deflated_entry = entries
      assert_equal(Zlib.crc32(stored_content), stored_entry.crc)
      assert_equal(Zlib.crc32(deflated_content), deflated_entry.crc)
      assert_equal(stored_content.bytesize, stored_entry.size)
      assert_equal(deflated_content.bytesize, deflated_entry.size)
      assert_equal(stored_content.bytesize, stored_entry.compressed_size)
      assert(deflated_entry.compressed_size < deflated_content.bytesize)
      assert_equal(0x08, stored_entry.gp_flags & 0x08)
      assert_equal(0x08, deflated_entry.gp_flags & 0x08)
    end

    local_header = io.string[0, 30]
    _signature, _version_needed, gp_flags, = local_header.unpack('VvvvvvVVVvv')
    assert_equal(0x08, gp_flags & 0x08)
  end

  def test_forward_only_handles_short_writes
    io = WriteOnlyIO.new(limit: 7)
    content = 'short writes must be retried' * 50

    ::Zip::OutputStream.write_stream(io) do |zos|
      zos.put_next_entry('stored.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
      zos.write(content)
    end

    ::Zip::File.open_buffer(StringIO.new(io.string)) do |zip_file|
      assert_equal(content, zip_file.read('stored.txt'))
    end
  end

  def test_forward_only_writes_encrypted_aes_entries
    password = 'password'
    content = 'encrypted forward-only content' * 20
    io = WriteOnlyIO.new

    ::Zip::OutputStream.write_stream(
      io,
      encrypter: ::Zip::AESEncrypter.new(
        password, ::Zip::AESEncryption::STRENGTH_128_BIT
      )
    ) do |zos|
      zos.put_next_entry('encrypted.txt')
      zos.write(content)
    end

    ::Zip::File.open_buffer(StringIO.new(io.string)) do |zip_file|
      entry = zip_file.get_entry('encrypted.txt')
      assert(entry.aes?)
      assert_equal(
        content,
        entry.get_input_stream(
          decrypter: ::Zip::AESDecrypter.new(
            password, ::Zip::AESEncryption::STRENGTH_128_BIT
          )
        ) { |stream| stream.read }
      )
    end
  end

  def test_forward_only_selects_zip64_before_entry_data_is_written
    io = WriteOnlyIO.new
    entry = ::Zip::Entry.new(nil, 'zero-sized.txt', size: 0)

    ::Zip::OutputStream.write_stream(io) do |zos|
      zos.put_next_entry(entry)
    end

    assert(entry.zip64?)
    assert_equal(
      Zip::VERSION_NEEDED_TO_EXTRACT_ZIP64,
      entry.instance_variable_get(:@version_needed_to_extract)
    )
    ::Zip::Entry.read_local_entry(StringIO.new(io.string)).tap do |local_entry|
      assert(local_entry.zip64?)
      assert_equal(0, local_entry.size)
      assert_equal(0, local_entry.compressed_size)
    end
  end

  def test_forward_only_can_disable_zip64
    io = WriteOnlyIO.new

    ::Zip::OutputStream.write_stream(io, zip64: false) do |zos|
      zos.put_next_entry('stored.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
      zos.write('small enough')
    end

    ::Zip::File.open_buffer(StringIO.new(io.string)) do |zip_file|
      entry = zip_file.get_entry('stored.txt')
      refute(entry.zip64?)
      assert_equal('small enough', zip_file.read(entry))
    end

  end

  def test_forward_only_raises_before_data_when_zip64_is_disabled_for_known_large_entry
    io = WriteOnlyIO.new

    error = assert_raises(Zip::Error) do
      ::Zip::OutputStream.write_stream(io, zip64: false) do |zos|
        zos.put_next_entry(
          ::Zip::Entry.new(nil, 'large.txt', size: 0x1_0000_0000)
        )
      end
    end

    assert_match(/Zip64/i, error.message)
    assert_equal(+'', io.string)
  end

  def test_forward_only_does_not_write_directory_after_a_header_write_error
    io = Class.new do
      attr_reader :written

      def initialize
        @written = +''.b
      end

      def write(data)
        @written << data
        raise IOError, 'broken pipe'
      end
    end

    target = io.new
    zos = ::Zip::OutputStream.new(target, stream: true, forward_only: true)
    assert_raises(IOError) { zos.put_next_entry('first.txt') }

    assert_raises(IOError) { zos.close }
    refute_includes(target.written, [Zip::CentralDirectory::END_OF_CD_SIG].pack('V'))
  end

  def test_forward_only_does_not_write_directory_after_a_data_write_error
    target = FailContentIO.new
    zos = ::Zip::OutputStream.new(target, stream: true, forward_only: true)

    zos.put_next_entry('first.txt', '', Zip::ExtraField.new, Zip::Entry::STORED)
    assert_raises(IOError) { zos.write('content') }
    assert_raises(IOError) { zos.close_buffer }

    refute_includes(target.string, [Zip::CentralDirectory::END_OF_CD_SIG].pack('V'))
  end

  def test_zip64_default_usage
    buffer = Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry('write_test')
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert(entry.zip64?)
    end
  end

  def test_zip64_default_usage_file
    ::Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.put_next_entry('write_test')
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(TEST_ZIP.zip_name) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert(entry.zip64?)
    end
  end

  def test_zip64_off_by_default
    Zip.write_zip64_support = false
    buffer = Zip::OutputStream.write_buffer do |zos|
      zos.put_next_entry('write_test')
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      refute(entry.zip64?)
    end
  end

  def test_zip64_off_by_default_file
    Zip.write_zip64_support = false
    ::Zip::OutputStream.open(TEST_ZIP.zip_name) do |zos|
      zos.put_next_entry('write_test')
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(TEST_ZIP.zip_name) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      refute(entry.zip64?)
    end
  end

  def test_zip64_and_ut_suppressed
    buffer = Zip::OutputStream.write_buffer(suppress_extra_fields: true) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test')
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      refute(entry.zip64?)
      refute(entry.absolute_time?)
    end
  end

  def test_only_zip64_suppressed
    buffer = Zip::OutputStream.write_buffer(suppress_extra_fields: :zip64) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test')
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      refute(entry.zip64?)
      assert(entry.absolute_time?)
    end
  end

  def test_zip64_and_ut_suppressed_file
    ::Zip::OutputStream.open(TEST_ZIP.zip_name, suppress_extra_fields: true) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test')
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(TEST_ZIP.zip_name) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      refute(entry.zip64?)
      refute(entry.absolute_time?)
    end
  end

  def test_only_zip64_suppressed_file
    ::Zip::OutputStream.open(TEST_ZIP.zip_name, suppress_extra_fields: :zip64) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test')
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(TEST_ZIP.zip_name) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      refute(entry.zip64?)
      assert(entry.absolute_time?)
    end
  end

  def test_ut_but_not_zip64_suppressed_with_large_size
    buffer = ::Zip::OutputStream.write_buffer(suppress_extra_fields: true) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test', size: 0x1_0000_0000)
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert(entry.zip64?)
      refute(entry.absolute_time?)
    end
  end

  def test_only_zip64_not_ut_suppressed_with_large_size
    buffer = ::Zip::OutputStream.write_buffer(suppress_extra_fields: :zip64) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test', size: 0x1_0000_0000)
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(buffer) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert(entry.zip64?)
      assert(entry.absolute_time?)
    end
  end

  def test_ut_but_not_zip64_suppressed_with_large_size_file
    ::Zip::OutputStream.open(TEST_ZIP.zip_name, suppress_extra_fields: true) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test', size: 0x1_0000_0000)
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(TEST_ZIP.zip_name) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert(entry.zip64?)
      refute(entry.absolute_time?)
    end
  end

  def test_only_zip64_not_ut_suppressed_with_large_size_file
    ::Zip::OutputStream.open(TEST_ZIP.zip_name, suppress_extra_fields: :zip64) do |zos|
      entry = ::Zip::Entry.new(nil, 'write_test', size: 0x1_0000_0000)
      entry.atime = Time.now
      zos.put_next_entry(entry)
      zos.write 'hello, world!'
    end

    Zip::InputStream.open(TEST_ZIP.zip_name) do |zis|
      entry = zis.get_next_entry
      assert_equal('write_test', entry.name)
      assert(entry.zip64?)
      assert(entry.absolute_time?)
    end
  end

  def assert_i_o_error_in_closed_stream
    assert_raises(IOError) do
      zos = ::Zip::OutputStream.new('test/data/generated/test_putOnClosedStream.zip')
      zos.close
      yield zos
    end
  end

  def write_test_zip(zos)
    TEST_ZIP.entry_names.each do |entry_name|
      zos.put_next_entry(entry_name)
      File.open(entry_name, 'rb') { |f| zos.write(f.read) }
    end
  end
end
