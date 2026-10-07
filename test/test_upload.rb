require "common"
require "tempfile"

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

  def test_sparse_upload_sets_logical_size_after_data_writes
    data = "ab" + "\0" * 6 + "cd"
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/path/to/remote", :long, 0x1A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "ab")
      channel.sends_packet(FXP_WRITE, :long, 2, :string, "handle", :int64, 8, :string, "cd")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_FSETSTAT, :long, 3, :string, "handle", :long, 1, :int64, 10)
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 4, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
    end

    expect_file("/path/to/local", data)

    assert_scripted_command do
      sftp.upload("/path/to/local", "/path/to/remote",
        :sparse => true, :read_size => 4, :sparse_threshold => 4)
    end
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

  def test_sparse_upload_merges_zero_runs_across_read_blocks_and_preserves_remote_size
    data = "ab" + "\0" * 6 + "cd"
    remote = MemorySftp.new("/sparse" => "old bytes that must not remain")
    events = []

    Tempfile.create(["sparse", ".bin"]) do |path|
      File.binwrite(path, data)
      Net::SFTP::Operations::Upload.new(remote, path, "/sparse",
        :sparse => true, :read_size => 4, :sparse_threshold => 4
      ) { |*args| events << args }.wait
    end

    assert_equal data, remote.files["/sparse"]
    writes = remote.calls.select { |call| call[:type] == :write }
    assert_equal [[0, "ab"], [8, "cd"]], writes.map { |call| [call[:offset], call[:data]] }
    assert_equal [{:type => :fsetstat, :size => 10}], remote.calls.select { |call| call[:type] == :fsetstat }.map { |call| call.slice(:type, :size) }
    progress_file = events.select { |event| event[0] == :progress }.last[2]
    assert_equal 10, progress_file.logical_bytes
    assert_equal 4, progress_file.sent_bytes
  end

  def test_sparse_upload_handles_trailing_zeros_and_an_entirely_zero_file
    trailing = MemorySftp.new
    Net::SFTP::Operations::Upload.new(trailing, StringIO.new("ab" + "\0" * 6), "/tail",
      :sparse => true, :read_size => 4, :sparse_threshold => 4).wait

    assert_equal "ab" + "\0" * 6, trailing.files["/tail"]
    assert_equal [[0, "ab"]], trailing.calls.select { |call| call[:type] == :write }.map { |call| [call[:offset], call[:data]] }
    assert_equal 8, trailing.files["/tail"].bytesize

    empty = MemorySftp.new
    events = []
    Net::SFTP::Operations::Upload.new(empty, StringIO.new("\0" * 8), "/empty",
      :sparse => true, :read_size => 4, :sparse_threshold => 4
    ) { |*args| events << args }.wait

    assert_equal "\0" * 8, empty.files["/empty"]
    assert_empty empty.calls.select { |call| call[:type] == :write }
    assert_equal [:hole, 0, 8], events.map { |event| [event[0], event[3], event[4]] }.find { |event| event[0] == :hole }
    assert_equal [{:type => :fsetstat, :size => 8}], empty.calls.select { |call| call[:type] == :fsetstat }.map { |call| call.slice(:type, :size) }
  end

  def test_sparse_upload_accepts_ordered_caller_ranges_and_io_input
    data = "ab" + "\0" * 6 + "cd"
    remote = MemorySftp.new
    events = []

    Net::SFTP::Operations::Upload.new(remote, StringIO.new(data), "/ranges",
      :data_intervals => [0...2, 8...10], :read_size => 4
    ) { |*args| events << args }.wait

    assert_equal data, remote.files["/ranges"]
    assert_equal [[0, "ab"], [8, "cd"]], remote.calls.select { |call| call[:type] == :write }.map { |call| [call[:offset], call[:data]] }
    progress_file = events.select { |event| event[0] == :progress }.last[2]
    assert_equal 10, progress_file.logical_bytes
    assert_equal 4, progress_file.sent_bytes
  end

  def test_sparse_upload_rejects_unordered_overlapping_and_out_of_bounds_ranges
    remote = MemorySftp.new
    [[[2, 1], [0, 1]], [[0, 2], [1, 2]], [[9, 2]], [[0, 0]]].each do |intervals|
      assert_raises(ArgumentError) do
        Net::SFTP::Operations::Upload.new(remote, StringIO.new("\0" * 10), "/bad",
          :data_intervals => intervals)
      end
    end
    assert_empty remote.calls
  end

  def test_non_sparse_upload_still_writes_every_byte_from_io
    data = "ab" + "\0" * 6 + "cd"
    remote = MemorySftp.new

    Net::SFTP::Operations::Upload.new(remote, StringIO.new(data), "/plain",
      :read_size => 4).wait

    assert_equal data, remote.files["/plain"]
    assert_equal [[0, data[0, 4]], [4, data[4, 4]], [8, data[8, 2]]],
      remote.calls.select { |call| call[:type] == :write }.map { |call| [call[:offset], call[:data]] }
    assert_empty remote.calls.select { |call| call[:type] == :fsetstat }
  end

  def test_sparse_write_failure_is_observable_and_does_not_set_size_or_close
    remote = MemorySftp.new
    remote.fail_next_write!

    error = assert_raises(Net::SFTP::StatusException) do
      Net::SFTP::Operations::Upload.new(remote, StringIO.new("ab" + "\0" * 6), "/fail",
        :sparse => true, :sparse_threshold => 4).wait
    end

    assert_equal 4, error.code
    assert_empty remote.calls.select { |call| call[:type] == :fsetstat }
    assert_empty remote.calls.select { |call| call[:type] == :close }
  end

  private

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

class MemoryRequest
  attr_accessor :response

  def initialize(session, properties={})
    @session = session
    @properties = properties
  end

  def [](key)
    @properties[key]
  end

  def []=(key, value)
    @properties[key] = value
  end

  def pending?
    @response.nil?
  end

  def wait
    @session.loop { pending? }
    self
  end
end

class MemoryResponse
  include Net::SFTP::Constants::StatusCodes

  attr_reader :request, :code, :message, :data

  def initialize(request, code=FX_OK, data={})
    @request = request
    @code = code
    @message = data[:message]
    @data = data
  end

  def [](key)
    @data[key]
  end

  def ok?
    code == FX_OK
  end
end

class MemorySftp
  include Net::SFTP::Constants::StatusCodes

  attr_reader :files, :calls

  def initialize(files={})
    @files = files
    @calls = []
    @queue = []
    @next_id = 0
    @fail_next_write = false
  end

  def logger
    @logger ||= Logger.new(File::NULL)
  end

  def fail_next_write!
    @fail_next_write = true
  end

  def loop
    while block_given? ? yield : @queue.any?
      callback, request, response = @queue.shift
      break unless callback
      request.response = response
      callback.call(response)
    end
  end

  def open(path, flags="r", options={}, &callback)
    record(:open, :path => path, :flags => flags, :options => options)
    @files[path] = "".b if flags == "w"
    respond(callback, :handle => "handle:#{path}")
  end

  def write(handle, offset, data, &callback)
    record(:write, :handle => handle, :offset => offset, :data => data.b)
    path = path_for_handle(handle)
    code = FX_OK
    if @fail_next_write
      code = FX_FAILURE
      @fail_next_write = false
    else
      current = @files[path]
      current = current.b.dup
      current << "\0".b * (offset - current.bytesize) if current.bytesize < offset
      current[offset, data.bytesize] = data.b
      @files[path] = current
    end
    respond(callback, {}, code)
  end

  def fsetstat(handle, attrs, &callback)
    record(:fsetstat, :handle => handle, :size => attrs[:size])
    path = path_for_handle(handle)
    @files[path] = @files[path].b.dup << "\0".b while @files[path].bytesize < attrs[:size]
    @files[path] = @files[path][0, attrs[:size]].b if @files[path].bytesize > attrs[:size]
    respond(callback)
  end

  def close(handle, &callback)
    record(:close, :handle => handle)
    respond(callback)
  end

  private

    def record(type, attributes)
      @calls << attributes.merge(:type => type)
    end

    def respond(callback, data={}, code=Net::SFTP::Constants::StatusCodes::FX_OK)
      request = MemoryRequest.new(self)
      response = MemoryResponse.new(request, code, data)
      @queue << [callback, request, response]
      request
    end

    def path_for_handle(handle)
      handle.sub("handle:", "")
    end
end
