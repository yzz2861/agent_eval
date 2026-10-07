require 'common'

class TextFileOperationsTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::Extensions

  # A minimal scripted SFTP stand-in. Read requests record their byte
  # offset and return consecutive chunks; seek requests jump the chunk
  # cursor back to a scripted position.
  class ScriptedSFTP
    attr_reader :read_offsets, :seek_lines

    def initialize(extensions = {})
      @extensions = extensions
      @chunks = nil
      @cursor = 0
      @read_offsets = []
      @seek_lines = []
    end

    def script(chunks, seek_chunks: nil, fail_after_seek: nil)
      @chunks = chunks
      @seek_chunks = seek_chunks
      @fail_after_seek = fail_after_seek
    end

    def extensions
      @extensions
    end

    def supports?(name)
      @extensions.key?(name)
    end

    def text_mode?
      true
    end

    def read!(_handle, offset, _length)
      @read_offsets << offset
      chunk = @chunks[@cursor]
      @cursor += 1
      chunk
    end

    def text_seek!(*args)
      line = args.last
      @seek_lines << line
      if @fail_after_seek && line == @fail_after_seek
        response = Object.new
        def response.eof?; false; end
        def response.ok?; false; end
        def response.code; 4; end
        def response.message; "seek failed"; end
        raise Net::SFTP::StatusException.new(response)
      end
      @cursor = 0
      @chunks = @seek_chunks if @seek_chunks
    end

    def close!(_handle); end
  end

  def sftp_with(chunks, extensions = {})
    sftp = ScriptedSFTP.new(extensions)
    sftp.script(chunks)
    file = Net::SFTP::Operations::TextFile.new(sftp, "handle")
    [sftp, file]
  end

  def test_new_file_should_start_at_line_zero_with_default_newline
    _sftp, file = sftp_with([nil])
    assert_equal "handle", file.handle
    assert_equal 0, file.lineno
    assert_equal "\n".b, file.newline
    assert_nil file.gets
    assert file.eof?
  end

  def test_gets_should_return_logical_lines_including_newline
    sftp, file = sftp_with(["alpha\nbeta\n", nil])
    assert_equal "alpha\n", file.gets
    assert_equal 1, file.lineno
    assert_equal "beta\n", file.gets
    assert_equal 2, file.lineno
    assert_nil file.gets
    assert file.eof?
    assert_equal [0, 11], sftp.read_offsets
  end

  def test_gets_should_return_final_line_without_newline
    sftp, file = sftp_with(["only line", nil])
    assert_equal "only line", file.gets
    assert_nil file.gets
    assert file.eof?
    assert_equal [0, 9], sftp.read_offsets
  end

  def test_gets_should_handle_empty_lines
    _sftp, file = sftp_with(["\n\nx\n", nil])
    assert_equal "\n", file.gets
    assert_equal "\n", file.gets
    assert_equal "x\n", file.gets
    assert_nil file.gets
  end

  def test_gets_should_decode_non_ascii_content_as_utf8
    payload = "h\u00e9llo \u{4e16}\u{754c}\n".b
    _sftp, file = sftp_with([payload, nil])
    line = file.gets
    assert_equal Encoding::UTF_8, line.encoding
    assert_equal "h\u00e9llo \u{4e16}\u{754c}\n", line
  end

  def test_gets_should_read_incrementally_across_responses
    sftp, file = sftp_with(["ab", "c\n", "d", nil])
    assert_equal "abc\n", file.gets
    assert_equal "d", file.gets
    assert_nil file.gets
    assert_equal [0, 2, 4, 5], sftp.read_offsets
  end

  def test_newline_split_across_responses_should_be_recognized_incrementally
    sftp, file = sftp_with(["abc\r", "\ndef\r", "\nend", nil], { NEWLINE => "\r\n" })
    assert_equal "\r\n".b, file.newline
    assert_equal "abc\r\n", file.gets
    assert_equal "def\r\n", file.gets
    assert_equal "end", file.gets
    assert_equal [0, 3, 8, 13], sftp.read_offsets
  end

  def test_lone_cr_should_not_be_treated_as_crlf_when_followed_by_other_byte
    _sftp, file = sftp_with(["abc\rdef\r\n", nil], { NEWLINE => "\r\n" })
    assert_equal "abc\rdef\r\n", file.gets
    assert_nil file.gets
  end

  def test_trailing_lone_cr_at_eof_should_be_returned_as_literal_content
    _sftp, file = sftp_with(["abc\r", nil], { NEWLINE => "\r\n" })
    assert_equal "abc\r", file.gets
    assert_nil file.gets
  end

  def test_crlf_split_over_more_than_two_responses_should_still_match
    sftp, file = sftp_with(["line1\r", "\n", "line2", nil], { NEWLINE => "\r\n" })
    assert_equal "line1\r\n", file.gets
    assert_equal "line2", file.gets
    assert_nil file.gets
    assert_equal [0, 5, 7, 12], sftp.read_offsets
  end

  def test_readline_should_raise_eof_error_at_end_of_file
    _sftp, file = sftp_with(["a\n", nil])
    assert_equal "a\n", file.readline
    assert_raises(EOFError) { file.readline }
  end

  def test_each_line_should_iterate_remaining_lines
    _sftp, file = sftp_with(["a\nb\nc", nil])
    lines = []
    assert_same file, file.each_line { |line| lines << line }
    assert_equal ["a\n", "b\n", "c"], lines
  end

  def test_each_line_without_block_should_return_enumerator
    _sftp, file = sftp_with(["x", nil])
    enum = file.each_line
    assert_instance_of Enumerator, enum
    assert_equal ["x"], enum.to_a
  end

  def test_seek_line_should_send_logical_coordinates_and_reset_stream
    sftp = ScriptedSFTP.new(TEXT_SEEK => "1")
    sftp.script(["third\n", nil])
    file = Net::SFTP::Operations::TextFile.new(sftp, "handle")

    assert_equal 3, file.seek_line(3)
    assert_equal 3, file.lineno
    assert_equal "third\n", file.gets
    assert_equal 4, file.lineno
    assert_equal [3], sftp.seek_lines
    assert_equal [0], sftp.read_offsets
  end

  def test_seek_line_should_coerce_numeric_arguments
    sftp, file = sftp_with([nil], TEXT_SEEK => "1")
    file.seek_line(7.0)
    assert_equal [7], sftp.seek_lines
  end

  def test_seek_line_should_reject_negative_lines_without_touching_server
    sftp, file = sftp_with([nil], TEXT_SEEK => "1")
    assert_raises(ArgumentError) { file.seek_line(-1) }
    assert_empty sftp.seek_lines
  end

  def test_seek_line_without_extension_should_raise_not_supported_and_not_fake_success
    sftp, file = sftp_with(["unread\n"])
    assert !file.seek_supported?
    assert_raises(Net::SFTP::NotSupported) { file.seek_line(2) }
    assert_empty sftp.seek_lines
    assert_raises(IOError) { file.gets }
  end

  def test_failed_seek_should_invalidate_buffered_data
    sftp = ScriptedSFTP.new(TEXT_SEEK => "1")
    sftp.script(["buffered\n"], :fail_after_seek => 99)
    file = Net::SFTP::Operations::TextFile.new(sftp, "handle")
    assert_equal "buffered\n", file.gets

    assert_raises(Net::SFTP::StatusException) { file.seek_line(99) }
    assert_raises(IOError) { file.gets }
    assert_raises(IOError) { file.readline }
    assert_raises(IOError) { file.eof? }
  end

  def test_successful_seek_after_failure_should_restore_reading
    sftp = ScriptedSFTP.new(TEXT_SEEK => "1")
    sftp.script(["initial\n"], :seek_chunks => ["again\n", nil],
                :fail_after_seek => 99)
    file = Net::SFTP::Operations::TextFile.new(sftp, "handle")

    assert_raises(Net::SFTP::StatusException) { file.seek_line(99) }
    assert_equal 0, file.seek_line(0)
    assert_equal "again\n", file.gets
  end

  def test_seek_past_eof_should_fail_and_not_pretend_line_exists
    sftp = ScriptedSFTP.new(TEXT_SEEK => "1")
    sftp.script(["x"], :fail_after_seek => 1000)
    file = Net::SFTP::Operations::TextFile.new(sftp, "handle")

    assert_raises(Net::SFTP::StatusException) { file.seek_line(1000) }
    assert_raises(IOError) { file.gets }
  end

  def test_rewind_should_seek_to_line_zero
    sftp, file = sftp_with([nil], TEXT_SEEK => "1")
    assert_equal 0, file.rewind
    assert_equal [0], sftp.seek_lines
    assert_equal 0, file.lineno
  end

  def test_text_file_should_not_expose_byte_coordinates
    _sftp, file = sftp_with([])
    assert_raises(NoMethodError) { file.pos }
    assert_raises(NoMethodError) { file.pos = 5 }
    assert_raises(NoMethodError) { file.read(10) }
    assert_raises(NoMethodError) { file.write("x") }
  end

  def test_close_should_close_handle_and_refuse_further_operations
    sftp = mock("sftp")
    sftp.stubs(:extensions).returns({})
    sftp.expects(:close!).with("handle")
    file = Net::SFTP::Operations::TextFile.new(sftp, "handle")
    file.close
    assert_nil file.handle
    assert_raises(IOError) { file.gets }
  end
end

class TextFileOpeningTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::Extensions

  def test_open_should_use_v4_text_mode_rules_and_server_newline
    sftp = stub("sftp")
    sftp.stubs(:version).returns(4)
    sftp.stubs(:text_mode?).returns(true)
    sftp.stubs(:extensions).returns(NEWLINE => "\n")
    sftp.expects(:open!).with("/file.txt", "r",
                             :permissions => nil, :text => true).returns("handle")

    file = Net::SFTP::Operations::TextFile.open(sftp, "/file.txt")
    assert_instance_of Net::SFTP::Operations::TextFile, file
    assert_equal "handle", file.handle
  end

  def test_open_should_report_not_supported_on_old_servers_without_opening
    sftp = stub("sftp")
    sftp.stubs(:version).returns(3)
    sftp.stubs(:text_mode?).returns(false)
    sftp.expects(:open!).never

    error = assert_raises(Net::SFTP::NotSupported) do
      Net::SFTP::Operations::TextFile.open(sftp, "/file.txt")
    end
    assert_match(/version 4/, error.message)
  end
end

class TextFileFactoryTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::Extensions

  def setup
    @sftp = stub("sftp")
    @sftp.stubs(:version).returns(4)
    @sftp.stubs(:text_mode?).returns(true)
    @sftp.stubs(:extensions).returns(TEXT_SEEK => "1")
    @factory = Net::SFTP::Operations::FileFactory.new(@sftp)
  end

  def test_open_text_without_block_returns_text_file
    @sftp.expects(:open!).with("/f.txt", "r",
                             :permissions => nil, :text => true).returns("h")
    f = @factory.open_text("/f.txt")
    assert_instance_of Net::SFTP::Operations::TextFile, f
  end

  def test_open_text_with_block_yields_and_closes
    @sftp.expects(:open!).returns("h")
    @sftp.expects(:close!).with("h")
    yielded = nil
    @factory.open_text("/f.txt") { |f| yielded = f }
    assert_instance_of Net::SFTP::Operations::TextFile, yielded
  end

  def test_open_text_closes_even_when_block_raises
    @sftp.expects(:open!).returns("h")
    @sftp.expects(:close!).with("h")
    assert_raises(RuntimeError) { @factory.open_text("/f.txt") { raise "boom" } }
  end

  def test_open_text_reports_old_server_without_binary_fallback
    @sftp = stub("old-sftp")
    @sftp.stubs(:version).returns(3)
    @sftp.stubs(:text_mode?).returns(false)
    @factory = Net::SFTP::Operations::FileFactory.new(@sftp)
    @sftp.expects(:open!).never
    assert_raises(Net::SFTP::NotSupported) { @factory.open_text("/f.txt") }
  end
end
