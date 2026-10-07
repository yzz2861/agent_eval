require "common"

class UploadTest < Net::SFTP::TestCase
  def setup
    prepare_progress!
  end

  def test_upload_file_should_send_file_contents
    expect_file_transfer("/path/to/local", "/path/to/remote", "here are the contents")
    assert_scripted_command { sftp.upload("/path/to/local", "/path/to/remote") }
  end

  def test_upload_file_without_remote_uses_filename_of_local_file
    expect_file_transfer("/path/to/local", "local", "here are the contents")

    assert_scripted_command do
      sftp.upload("/path/to/local") { |*args| record_progress(args) }
    end

    assert_progress_reported_open(:remote => "local")
    assert_progress_reported_put(0, "here are the contents", :remote => "local")
    assert_progress_reported_close(:remote => "local")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_upload_file_with_progress_should_report_progress
    expect_file_transfer("/path/to/local", "/path/to/remote", "here are the contents")

    assert_scripted_command do
      sftp.upload("/path/to/local", "/path/to/remote") { |*args| record_progress(args) }
    end

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, "here are the contents", :remote => "/path/to/remote")
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_upload_file_with_progress_handler_should_report_progress
    expect_file_transfer("/path/to/local", "/path/to/remote", "here are the contents")

    assert_scripted_command do
      sftp.upload("/path/to/local", "/path/to/remote", :progress => ProgressHandler.new(@progress))
    end

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, "here are the contents", :remote => "/path/to/remote")
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_upload_file_should_read_chunks_of_size(requested_size=nil)
    size = requested_size || Net::SFTP::Operations::Upload::DEFAULT_READ_SIZE
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/path/to/remote", :long, 0x1A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "a" * size)
      channel.sends_packet(FXP_WRITE, :long, 2, :string, "handle", :int64, size, :string, "b" * size)
      channel.sends_packet(FXP_WRITE, :long, 3, :string, "handle", :int64, size*2, :string, "c" * size)
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_WRITE, :long, 4, :string, "handle", :int64, size*3, :string, "d" * size)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 5, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 5, :long, 0)
    end

    expect_file("/path/to/local", "a" * size + "b" * size + "c" * size + "d" * size)

    assert_scripted_command do
      opts = {}
      opts[:read_size] = size if requested_size
      sftp.upload("/path/to/local", "/path/to/remote", opts)
    end
  end

  def test_upload_file_with_custom_read_size_should_read_chunks_of_that_size
    test_upload_file_should_read_chunks_of_size(100)
  end

  def test_upload_file_with_custom_requests_should_start_that_many_writes
    size = Net::SFTP::Operations::Upload::DEFAULT_READ_SIZE
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/path/to/remote", :long, 0x1A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "a" * size)
      channel.sends_packet(FXP_WRITE, :long, 2, :string, "handle", :int64, size, :string, "b" * size)
      channel.sends_packet(FXP_WRITE, :long, 3, :string, "handle", :int64, size*2, :string, "c" * size)
      channel.sends_packet(FXP_WRITE, :long, 4, :string, "handle", :int64, size*3, :string, "d" * size)
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 5, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 5, :long, 0)
    end

    expect_file("/path/to/local", "a" * size + "b" * size + "c" * size + "d" * size)

    assert_scripted_command do
      sftp.upload("/path/to/local", "/path/to/remote", :requests => 3)
    end
  end

  def test_upload_directory_should_mirror_directory_structure_remotely
    prepare_directory

    assert_scripted_command do
      sftp.upload("/path/to/local", "/path/to/remote", :mkdir => true)
    end
  end

  def test_upload_directory_with_handler_should_report_progress
    prepare_directory

    assert_scripted_command do
      sftp.upload("/path/to/local", "/path/to/remote", :mkdir => true) { |*args| record_progress(args) }
    end

    assert_progress_reported_open(:remote => "/path/to/remote/file1")
    assert_progress_reported_open(:remote => "/path/to/remote/file2")
    assert_progress_reported_open(:remote => "/path/to/remote/file3")
    assert_progress_reported_mkdir("/path/to/remote/subdir")
    assert_progress_reported_open(:remote => "/path/to/remote/subdir/other1")
    assert_progress_reported_open(:remote => "/path/to/remote/subdir/other2")
    assert_progress_reported_put(0, "contents of file1", :remote => "/path/to/remote/file1")
    assert_progress_reported_put(0, "contents of file2", :remote => "/path/to/remote/file2")
    assert_progress_reported_put(0, "contents of file3", :remote => "/path/to/remote/file3")
    assert_progress_reported_close(:remote => "/path/to/remote/file1")
    assert_progress_reported_put(0, "contents of other1", :remote => "/path/to/remote/subdir/other1")
    assert_progress_reported_put(0, "contents of other2", :remote => "/path/to/remote/subdir/other2")
    assert_progress_reported_close(:remote => "/path/to/remote/file2")
    assert_progress_reported_close(:remote => "/path/to/remote/file3")
    assert_progress_reported_close(:remote => "/path/to/remote/subdir/other1")
    assert_progress_reported_close(:remote => "/path/to/remote/subdir/other2")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_upload_io_should_send_io_as_file
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/path/to/remote", :long, 0x1A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "this is some text")
      channel.sends_packet(FXP_CLOSE, :long, 2, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    assert_scripted_command do
      sftp.upload(StringIO.new("this is some text"), "/path/to/remote")
    end
  end

  def test_sparse_upload_skips_large_zero_region
    data = "AAAA".b + zeros(100_000) + "BBBB".b
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal [["/path/to/remote", 0, "AAAA"], ["/path/to/remote", 100_004, "BBBB"]],
      writes(session).map { |op| op[1..3] }
    assert session.operations.none? { |op| op[0] == :fsetstat }

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, "AAAA")
    assert_progress_reported_skip(4, 100_000)
    assert_progress_reported_put(100_004, "BBBB")
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_sparse_upload_merges_zero_runs_across_read_blocks
    data = "AA".b + zeros(10_000) + "BB".b
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1000)

    assert_equal data, session.remote("/path/to/remote")

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, "AA")
    assert_progress_reported_skip(2, 10_000)
    assert_progress_reported_put(10_002, "BB")
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_sparse_upload_with_zero_tail_resizes_remote_to_logical_size
    data = "DATA".b + zeros(50_000)
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal data.bytesize, session.remote("/path/to/remote").bytesize
    assert_equal [["/path/to/remote", { :size => 50_004 }]],
      session.operations.select { |op| op[0] == :fsetstat }.map { |op| op[1..2] }

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, "DATA")
    assert_progress_reported_skip(4, 50_000)
    assert_progress_reported_resize(50_004)
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_sparse_upload_with_all_zero_file_sends_no_data
    data = zeros(60_000)
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal [], writes(session)
    assert_equal [["/path/to/remote", { :size => 60_000 }]],
      session.operations.select { |op| op[0] == :fsetstat }.map { |op| op[1..2] }

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_skip(0, 60_000)
    assert_progress_reported_resize(60_000)
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_sparse_upload_sends_small_zero_runs_literally
    data = "AA".b + zeros(100) + "BB".b
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal [["/path/to/remote", 0, data]], writes(session).map { |op| op[1..3] }
    assert session.operations.none? { |op| op[0] == :fsetstat }

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, data)
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_sparse_upload_with_extents_sends_only_given_extents
    data = "AAAA".b + zeros(100_000) + "BBBB".b + zeros(50_000)
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :extents => [[0, 4], [100_004, 4]] }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal [["/path/to/remote", 0, "AAAA"], ["/path/to/remote", 100_004, "BBBB"]],
      writes(session).map { |op| op[1..3] }
    assert_equal [["/path/to/remote", { :size => 150_008 }]],
      session.operations.select { |op| op[0] == :fsetstat }.map { |op| op[1..2] }

    assert_progress_reported_open(:remote => "/path/to/remote")
    assert_progress_reported_put(0, "AAAA")
    assert_progress_reported_skip(4, 100_000)
    assert_progress_reported_put(100_004, "BBBB")
    assert_progress_reported_skip(100_008, 50_000)
    assert_progress_reported_resize(150_008)
    assert_progress_reported_close(:remote => "/path/to/remote")
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_sparse_upload_with_unsorted_extents_raises
    expect_file("/path/to/local", "AAAA".b + zeros(100))
    assert_raises(ArgumentError) do
      memory_upload("/path/to/local", "/path/to/remote",
        :sparse => { :extents => [[50, 4], [0, 4]] })
    end
  end

  def test_sparse_upload_with_overlapping_extents_raises
    expect_file("/path/to/local", "AAAA".b + zeros(100))
    assert_raises(ArgumentError) do
      memory_upload("/path/to/local", "/path/to/remote",
        :sparse => { :extents => [[0, 10], [5, 4]] })
    end
  end

  def test_sparse_upload_with_out_of_bounds_extents_raises
    expect_file("/path/to/local", "AAAA".b + zeros(100))
    assert_raises(ArgumentError) do
      memory_upload("/path/to/local", "/path/to/remote",
        :sparse => { :extents => [[0, 4], [100, 10]] })
    end
  end

  def test_sparse_upload_with_extents_requires_seekable_source
    io = Object.new
    def io.read(length); nil; end
    def io.size; 100; end

    assert_raises(ArgumentError) do
      Net::SFTP::Operations::Upload.new(MemoryRemoteSession.new, io, "/path/to/remote",
        :sparse => { :extents => [[0, 4]] })
    end
  end

  def test_sparse_upload_with_invalid_option_raises
    expect_file("/path/to/local", "AAAA".b)
    assert_raises(ArgumentError) do
      memory_upload("/path/to/local", "/path/to/remote", :sparse => "yes")
    end
  end

  def test_sparse_upload_with_invalid_min_hole_raises
    expect_file("/path/to/local", "AAAA".b)
    assert_raises(ArgumentError) do
      memory_upload("/path/to/local", "/path/to/remote", :sparse => { :min_hole => 0 })
    end
  end

  def test_sparse_upload_write_failure_raises_status_exception
    data = "AAAA".b + zeros(100_000) + "BBBB".b
    expect_file("/path/to/local", data)

    session = MemoryRemoteSession.new
    upload = Net::SFTP::Operations::Upload.new(session, "/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)
    session.fail_next_write = true

    assert_raises(Net::SFTP::StatusException) { upload.wait }
  end

  def test_sparse_upload_io_input_should_send_io_as_file
    data = "this ".b + zeros(100_000) + "is some text".b
    session = memory_upload(StringIO.new(data), "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal [["/path/to/remote", 0, "this "], ["/path/to/remote", 100_005, "is some text"]],
      writes(session).map { |op| op[1..3] }
  end

  def test_non_sparse_upload_sends_zero_regions_and_needs_no_resize
    data = "AA".b + zeros(10_000) + "BB".b
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote", :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")
    assert session.operations.none? { |op| op[0] == :fsetstat }
    sent = writes(session).map { |op| op[3].bytesize }.inject(0, :+)
    assert_equal data.bytesize, sent
  end

  def test_sparse_upload_overwrites_existing_remote_without_stale_bytes
    data = "AA".b + zeros(100_000) + "BB".b
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      { :sparse => { :min_hole => 4096 }, :read_size => 1024 },
      "/path/to/remote" => "X".b * 200_000)

    assert_equal data, session.remote("/path/to/remote")
    assert_equal data.bytesize, session.remote("/path/to/remote").bytesize
    open = session.operations.find { |op| op[0] == :open }
    assert_equal "w", open[2]
  end

  def test_sparse_upload_reports_logical_and_sent_bytes_separately
    data = "AA".b + zeros(10_000) + "BB".b + zeros(10_000) + "CC".b + zeros(10_000)
    expect_file("/path/to/local", data)

    session = memory_upload("/path/to/local", "/path/to/remote",
      :sparse => { :min_hole => 4096 }, :read_size => 1024)

    assert_equal data, session.remote("/path/to/remote")

    sent = 0
    skipped = 0
    @progress.each do |event|
      sent += event[4].bytesize if event[0] == :put
      skipped += event[4] if event[0] == :skip
    end
    assert_equal 6, sent
    assert_equal 30_000, skipped
    assert_equal data.bytesize, sent + skipped
  end

  private

    def zeros(length)
      "\x00".b * length
    end

    def memory_upload(local, remote, options={}, remote_contents={})
      session = MemoryRemoteSession.new(remote_contents)
      upload = Net::SFTP::Operations::Upload.new(session, local, remote, options) do |*args|
        record_progress(args)
      end
      upload.wait
      session
    end

    def writes(session)
      session.operations.select { |op| op[0] == :write }
    end

    def assert_progress_reported_skip(offset, length, expect={})
      assert_equal offset, current_event[3]
      assert_equal length, current_event[4]
      assert_progress_reported(:skip, expect)
    end

    def assert_progress_reported_resize(size, expect={})
      assert_equal size, current_event[3]
      assert_progress_reported(:resize, expect)
    end

    def prepare_directory
      expect_directory("/path/to/local", %w(. .. file1 file2 file3 subdir))
      expect_directory("/path/to/local/subdir", %w(. .. other1 other2))
      expect_file("/path/to/local/file1", "contents of file1")
      expect_file("/path/to/local/file2", "contents of file2")
      expect_file("/path/to/local/file3", "contents of file3")
      expect_file("/path/to/local/subdir/other1", "contents of other1")
      expect_file("/path/to/local/subdir/other2", "contents of other2")

      expect_sftp_session :server_version => 3 do |ch|
        ch.sends_packet(FXP_MKDIR, :long, 0, :string, "/path/to/remote", :long, 0)
        ch.gets_packet(FXP_STATUS, :long, 0, :long, 0)
        ch.sends_packet(FXP_OPEN, :long, 1, :string, "/path/to/remote/file1", :long, 0x1A, :long, 0)
        ch.sends_packet(FXP_OPEN, :long, 2, :string, "/path/to/remote/file2", :long, 0x1A, :long, 0)
        ch.sends_packet(FXP_OPEN, :long, 3, :string, "/path/to/remote/file3", :long, 0x1A, :long, 0)
        ch.sends_packet(FXP_MKDIR, :long, 4, :string, "/path/to/remote/subdir", :long, 0)
        ch.sends_packet(FXP_OPEN, :long, 5, :string, "/path/to/remote/subdir/other1", :long, 0x1A, :long, 0)
        ch.sends_packet(FXP_OPEN, :long, 6, :string, "/path/to/remote/subdir/other2", :long, 0x1A, :long, 0)
        ch.gets_packet(FXP_HANDLE, :long, 1, :string, "hfile1")
        ch.sends_packet(FXP_WRITE, :long, 7, :string, "hfile1", :int64, 0, :string, "contents of file1")
        ch.gets_packet(FXP_HANDLE, :long, 2, :string, "hfile2")
        ch.sends_packet(FXP_WRITE, :long, 8, :string, "hfile2", :int64, 0, :string, "contents of file2")
        ch.gets_packet(FXP_HANDLE, :long, 3, :string, "hfile3")
        ch.sends_packet(FXP_WRITE, :long, 9, :string, "hfile3", :int64, 0, :string, "contents of file3")
        ch.gets_packet(FXP_STATUS, :long, 4, :long, 0)
        ch.gets_packet(FXP_HANDLE, :long, 5, :string, "hother1")
        ch.sends_packet(FXP_CLOSE, :long, 10, :string, "hfile1")
        ch.sends_packet(FXP_WRITE, :long, 11, :string, "hother1", :int64, 0, :string, "contents of other1")
        ch.gets_packet(FXP_HANDLE, :long, 6, :string, "hother2")
        ch.sends_packet(FXP_WRITE, :long, 12, :string, "hother2", :int64, 0, :string, "contents of other2")
        ch.gets_packet(FXP_STATUS, :long, 7, :long, 0)
        ch.sends_packet(FXP_CLOSE, :long, 13, :string, "hfile2")
        ch.gets_packet(FXP_STATUS, :long, 8, :long, 0)
        ch.sends_packet(FXP_CLOSE, :long, 14, :string, "hfile3")
        ch.gets_packet(FXP_STATUS, :long, 9, :long, 0)
        ch.sends_packet(FXP_CLOSE, :long, 15, :string, "hother1")
        ch.gets_packet(FXP_STATUS, :long, 10, :long, 0)
        ch.sends_packet(FXP_CLOSE, :long, 16, :string, "hother2")
        ch.gets_packet(FXP_STATUS, :long, 11, :long, 0)
        ch.gets_packet(FXP_STATUS, :long, 12, :long, 0)
        ch.gets_packet(FXP_STATUS, :long, 13, :long, 0)
        ch.gets_packet(FXP_STATUS, :long, 14, :long, 0)
        ch.gets_packet(FXP_STATUS, :long, 15, :long, 0)
        ch.gets_packet(FXP_STATUS, :long, 16, :long, 0)
      end
    end

    def expect_file(path, data)
      File.stubs(:directory?).with(path).returns(false)
      File.stubs(:exist?).with(path).returns(true)
      file = StringIO.new(data)
      file.stubs(:stat).returns(stub("stat", :size => data.length))
      File.stubs(:open).with(path, "rb").returns(file)
    end

    def expect_directory(path, entries)
      Dir.stubs(:entries).with(path).returns(entries)
      File.stubs(:directory?).with(path).returns(true)
    end

    def expect_file_transfer(local, remote, data)
      expect_sftp_session :server_version => 3 do |channel|
        channel.sends_packet(FXP_OPEN, :long, 0, :string, remote, :long, 0x1A, :long, 0)
        channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
        channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, data)
        channel.sends_packet(FXP_CLOSE, :long, 2, :string, "handle")
        channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
        channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      end

      expect_file(local, data)
    end
end

# An in-memory model of a remote SFTP server, used to verify that the
# sequence of open/write/fsetstat/close operations issued by an upload
# reconstructs the expected remote file contents. Opening a file for
# writing truncates it (mirroring the SSH_FXF_TRUNC semantics the uploader
# relies on), and unwritten regions read back as zero bytes.
class MemoryRemoteSession
  class Request
    def initialize(callback)
      @callback = callback
      @properties = {}
    end

    def [](key)
      @properties[key.to_sym]
    end

    def []=(key, value)
      @properties[key.to_sym] = value
    end

    def respond(response)
      @callback.call(response) if @callback
    end
  end

  class Response
    def initialize(request, ok, attrs={})
      @request, @ok, @attrs = request, ok, attrs
    end

    attr_reader :request

    def ok?
      @ok
    end

    def [](key)
      @attrs[key]
    end

    def code
      ok? ? 0 : 4
    end

    def message
      ok? ? "success" : "failure"
    end
  end

  attr_reader :operations
  attr_accessor :fail_next_write

  def initialize(contents={})
    @files = {}
    contents.each { |path, data| @files[path] = data.b }
    @handles = {}
    @pending = []
    @operations = []
    @handle_counter = 0
    @fail_next_write = false
  end

  def logger
    nil
  end

  def remote(path)
    @files[path]
  end

  def loop
    until @pending.empty?
      request, response = @pending.shift
      request.respond(response)
    end
  end

  def open(path, flags, options={}, &callback)
    request = Request.new(callback)
    @operations << [:open, path, flags]
    @files[path] = +"" if flags.to_s.include?("w")
    handle = "handle#{@handle_counter += 1}"
    @handles[handle] = path
    @pending << [request, Response.new(request, true, :handle => handle)]
    request
  end

  def write(handle, offset, data, &callback)
    request = Request.new(callback)
    path = @handles[handle]
    @operations << [:write, path, offset, data.dup]
    if fail_next_write
      self.fail_next_write = false
      @pending << [request, Response.new(request, false)]
    else
      buffer = @files[path]
      buffer << ("\x00".b * (offset - buffer.bytesize)) if offset > buffer.bytesize
      buffer[offset, data.bytesize] = data.b
      @pending << [request, Response.new(request, true)]
    end
    request
  end

  def fsetstat(handle, attrs, &callback)
    request = Request.new(callback)
    path = @handles[handle]
    @operations << [:fsetstat, path, attrs]
    if attrs[:size]
      buffer = @files[path]
      if attrs[:size] < buffer.bytesize
        buffer.slice!(attrs[:size]..-1)
      else
        buffer << ("\x00".b * (attrs[:size] - buffer.bytesize))
      end
    end
    @pending << [request, Response.new(request, true)]
    request
  end

  def close(handle, &callback)
    request = Request.new(callback)
    @operations << [:close, @handles.delete(handle)]
    @pending << [request, Response.new(request, true)]
    request
  end
end
