require 'common'

class TextReaderTest < Net::SFTP::TestCase
  def setup
    @sftp = mock("sftp")
    @reader = Net::SFTP::Operations::TextReader.new(@sftp, "handle", "\r\n")
  end

  def test_newline_should_default_to_line_feed
    reader = Net::SFTP::Operations::TextReader.new(@sftp, "handle")
    assert_equal "\n", reader.newline
  end

  def test_empty_newline_should_fall_back_to_default
    reader = Net::SFTP::Operations::TextReader.new(@sftp, "handle", "")
    assert_equal "\n", reader.newline
  end

  def test_gets_should_return_lines_terminated_by_server_newline
    @sftp.expects(:read!).with("handle", 0, 8192).returns("one\r\ntwo\r\nthree")
    @sftp.expects(:read!).with("handle", 15, 8192).twice.returns(nil)

    assert_equal "one\r\n", @reader.gets
    assert_equal 1, @reader.lineno
    assert_equal "two\r\n", @reader.gets
    assert_equal 2, @reader.lineno
    assert_equal "three", @reader.gets
    assert_equal 3, @reader.lineno
    assert @reader.eof?
    assert_nil @reader.gets
  end

  def test_gets_should_recognize_newline_spanning_multiple_responses
    @sftp.expects(:read!).with("handle", 0, 8192).returns("one\r")
    @sftp.expects(:read!).with("handle", 4, 8192).returns("\ntwo\r\n")

    assert_equal "one\r\n", @reader.gets
    assert_equal "two\r\n", @reader.gets
  end

  def test_gets_should_return_empty_lines_as_bare_newlines
    reader = Net::SFTP::Operations::TextReader.new(@sftp, "handle")
    @sftp.expects(:read!).with("handle", 0, 8192).returns("a\n\n\nb\n")
    @sftp.expects(:read!).with("handle", 6, 8192).returns(nil)

    assert_equal "a\n", reader.gets
    assert_equal "\n", reader.gets
    assert_equal "\n", reader.gets
    assert_equal "b\n", reader.gets
    assert_nil reader.gets
  end

  def test_gets_should_handle_non_ascii_content_and_advance_by_bytes
    data = "h\xC3\xA9llo\n".dup.force_encoding(Encoding::BINARY)
    reader = Net::SFTP::Operations::TextReader.new(@sftp, "handle")

    @sftp.expects(:read!).with("handle", 0, 8192).returns(data)
    @sftp.expects(:read!).with("handle", 7, 8192).returns(nil)

    assert_equal data, reader.gets
    assert_nil reader.gets
  end

  def test_readline_should_raise_eof_error_when_no_data_remains
    @sftp.expects(:read!).with("handle", 0, 8192).returns(nil)
    assert_raises(EOFError) { @reader.readline }
  end

  def test_eof_should_be_false_until_remote_eof_and_buffer_drained
    @sftp.expects(:read!).with("handle", 0, 8192).returns("a\r\n")
    refute @reader.eof?
    assert_equal "a\r\n", @reader.gets
    refute @reader.eof?

    @sftp.expects(:read!).with("handle", 3, 8192).returns(nil)
    assert_nil @reader.gets
    assert @reader.eof?
  end

  def test_seek_line_should_position_reader_at_server_reported_offset
    @sftp.expects(:text_seek!).with("handle", 2).returns(11)
    @sftp.expects(:read!).with("handle", 11, 8192).returns("three\r\n")

    assert_equal 2, @reader.seek_line(2)
    assert_equal 2, @reader.lineno
    assert_equal "three\r\n", @reader.gets
    assert_equal 3, @reader.lineno
  end

  def test_seek_line_should_discard_previously_buffered_data
    @sftp.expects(:read!).with("handle", 0, 8192).returns("one\r\ntwo\r\n")
    assert_equal "one\r\n", @reader.gets

    @sftp.expects(:text_seek!).with("handle", 0).returns(0)
    @sftp.expects(:read!).with("handle", 0, 8192).returns("one\r\n")

    @reader.seek_line(0)
    assert_equal "one\r\n", @reader.gets
  end

  def test_failed_seek_line_should_invalidate_buffer_and_keep_position
    @sftp.expects(:read!).with("handle", 0, 8192).returns("one\r\ntwo\r\n")
    assert_equal "one\r\n", @reader.gets

    @sftp.expects(:text_seek!).with("handle", 9).raises(status_exception(8))
    assert_raises(Net::SFTP::StatusException) { @reader.seek_line(9) }
    assert_equal 1, @reader.lineno

    # the buffer was invalidated, so the current line is re-fetched from
    # its remote offset rather than served from stale buffered bytes
    @sftp.expects(:read!).with("handle", 5, 8192).returns("two\r\n")
    assert_equal "two\r\n", @reader.gets
    assert_equal 2, @reader.lineno
  end

  def test_seek_line_should_reset_eof_flag
    @sftp.expects(:read!).with("handle", 0, 8192).returns(nil)
    assert_nil @reader.gets
    assert @reader.eof?

    @sftp.expects(:text_seek!).with("handle", 0).returns(0)
    @reader.seek_line(0)
    refute @reader.eof?
  end

  def test_seek_line_with_negative_line_number_should_raise_argument_error
    assert_raises(ArgumentError) { @reader.seek_line(-1) }
  end

  def test_pos_assignment_should_raise_argument_error
    assert_raises(ArgumentError) { @reader.pos = 12 }
  end

  def test_each_line_should_yield_each_remaining_line
    @sftp.expects(:read!).with("handle", 0, 8192).returns("one\r\ntwo\r\n")
    @sftp.expects(:read!).with("handle", 10, 8192).returns(nil)

    lines = []
    @reader.each_line { |line| lines << line }
    assert_equal ["one\r\n", "two\r\n"], lines
  end

  def test_close_should_close_handle_and_set_handle_to_nil
    @sftp.expects(:close!).with("handle")
    @reader.close
    assert_nil @reader.handle
  end

  private

    def status_exception(code)
      response = Net::SFTP::Response.new(nil, :code => code)
      Net::SFTP::StatusException.new(response)
    end
end
