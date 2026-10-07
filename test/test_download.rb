require "common"

class DownloadTest < Net::SFTP::TestCase
  FXP_DATA_CHUNK_SIZE = 1024

  def setup
    prepare_progress!
  end

  def test_download_file_should_transfer_remote_to_local
    local = "/path/to/local"
    remote = "/path/to/remote"
    text = "this is some text\n"

    expect_file_transfer(remote, text)

    file = StringIO.new
    File.stubs(:open).with(local, "wb").returns(file)

    assert_scripted_command { sftp.download(remote, local) }
    assert_equal text, file.string
  end

  def test_download_file_should_transfer_remote_to_local_in_spite_of_fragmentation
    local = "/path/to/local"
    remote = "/path/to/remote"
    text = "this is some text\n"

    expect_file_transfer(remote, text, :fragment_len => 1)

    file = StringIO.new
    File.stubs(:open).with(local, "wb").returns(file)

    assert_scripted_command { sftp.download(remote, local) }
    assert_equal text, file.string
  end

  def test_download_large_file_should_transfer_remote_to_local
    local = "/path/to/local"
    remote = "/path/to/remote"
    text = "0123456789" * 1024

    file = prepare_large_file_download(local, remote, text)

    assert_scripted_command { sftp.download(remote, local, :read_size => 1024) }
    assert_equal text, file.string
  end

  def test_download_large_file_should_handle_too_large_read_size
    local = "/path/to/local"
    remote = "/path/to/remote"
    text = "0123456789" * 1024

    # some servers put upper bound on the max read_size value and send less data than requested
    too_large_read_size = FXP_DATA_CHUNK_SIZE + 1
    file = prepare_large_file_download(local, remote, text, too_large_read_size)

    assert_scripted_command { sftp.download(remote, local, :read_size => too_large_read_size) }
    assert_equal text, file.string
  end

  def test_download_large_file_with_progress_should_report_progress
    local = "/path/to/local"
    remote = "/path/to/remote"
    text = "0123456789" * 1024

    file = prepare_large_file_download(local, remote, text)

    assert_scripted_command do
      sftp.download(remote, local, :read_size => 1024) do |*args|
        record_progress(args)
      end
    end

    assert_equal text, file.string

    assert_progress_reported_open :remote => "/path/to/remote"
    assert_progress_reported_get     0, 1024
    assert_progress_reported_get  1024, 1024
    assert_progress_reported_get  2048, 1024
    assert_progress_reported_get  3072, 1024
    assert_progress_reported_get  4096, 1024
    assert_progress_reported_get  5120, 1024
    assert_progress_reported_get  6144, 1024
    assert_progress_reported_get  7168, 1024
    assert_progress_reported_get  8192, 1024
    assert_progress_reported_get  9216, 1024
    assert_progress_reported_close
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_download_directory_should_mirror_directory_locally
    file1, file2 = prepare_directory_tree_download("/path/to/local", "/path/to/remote")

    assert_scripted_command do
      sftp.download("/path/to/remote", "/path/to/local", :recursive => true)
    end

    assert_equal "contents of file1", file1.string
    assert_equal "contents of file2", file2.string
  end

  def test_download_directory_with_progress_should_report_progress
    file1, file2 = prepare_directory_tree_download("/path/to/local", "/path/to/remote")

    assert_scripted_command do
      sftp.download("/path/to/remote", "/path/to/local", :recursive => true) do |*args|
        record_progress(args)
      end
    end

    assert_equal "contents of file1", file1.string
    assert_equal "contents of file2", file2.string

    assert_progress_reported_mkdir "/path/to/local"
    assert_progress_reported_mkdir "/path/to/local/subdir1"
    assert_progress_reported_open  :remote => "/path/to/remote/file1"
    assert_progress_reported_open  :remote => "/path/to/remote/subdir1/file2"
    assert_progress_reported_get   0, "contents of file1"
    assert_progress_reported_close :remote => "/path/to/remote/file1"
    assert_progress_reported_get   0, "contents of file2"
    assert_progress_reported_close :remote => "/path/to/remote/subdir1/file2"
    assert_progress_reported_finish
    assert_no_more_reported_events
  end

  def test_download_file_should_transfer_remote_to_local_buffer
    remote = "/path/to/remote"
    text = "this is some text\n"

    expect_file_transfer(remote, text)

    local = StringIO.new

    assert_scripted_command { sftp.download(remote, local) }
    assert_equal text, local.string
  end

  def test_download_directory_to_buffer_should_fail
    expect_sftp_session :server_version => 3
    Net::SSH::Test::Extensions::IO.with_test_extension do
      assert_raises(ArgumentError) { sftp.download("/path/to/remote", StringIO.new, :recursive => true) }
    end
  end

  def limits_blob(read_limit, write_limit, open_handles)
    Net::SSH::Buffer.from(:long, 1,
                          :int64, read_limit,
                          :int64, write_limit,
                          :int64, open_handles).to_s
  end

  def test_download_respects_negotiated_read_packet_limit
    local = "/path/to/local"
    remote = "/path/to/remote"
    text = "0123456789abcdefghij"

    # A 20-byte FXP_DATA cap leaves 11 payload bytes after the 9 bytes of
    # type/request-id/string-length encoding. The long handle shows that
    # read sizing stays valid even though handle length varies.
    handle = "long-handle-name"
    expect_sftp_session(:server_version => 3, :extensions => {
      Net::SFTP::Limits::EXTENSION_NAME => limits_blob(20, 1000, 100)
    }) do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, remote, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, handle)
      channel.sends_packet(FXP_READ, :long, 1, :string, handle, :int64, 0,  :long, 11)
      channel.gets_packet(FXP_DATA, :long, 1, :string, text[0, 11])
      channel.sends_packet(FXP_READ, :long, 2, :string, handle, :int64, 11, :long, 11)
      channel.gets_packet(FXP_DATA, :long, 2, :string, text[11, 11])
      channel.sends_packet(FXP_READ, :long, 3, :string, handle, :int64, 20, :long, 11)
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 1)
      channel.sends_packet(FXP_CLOSE, :long, 4, :string, handle)
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
    end

    file = StringIO.new
    File.stubs(:open).with(local, "wb").returns(file)

    assert_scripted_command { sftp.download(remote, local) }
    assert_equal text, file.string
  end

  def test_download_recursive_respects_negotiated_open_handles_limit
    local = "/path/to/local"
    remote = "/path/to/remote"
    file1, file2 = prepare_limited_directory_tree(local, remote)

    downloader = nil
    assert_scripted_command do
      downloader = sftp.download(remote, local, :recursive => true)
    end

    assert_equal "f1", file1.string
    assert_equal "f2", file2.string
    assert_equal 2, downloader.peak_open_handles
  end

  def test_download_recursive_works_with_single_handle_budget
    local = "/path/to/local"
    remote = "/path/to/remote"
    expect_sftp_session(:server_version => 3, :extensions => {
      Net::SFTP::Limits::EXTENSION_NAME => limits_blob(100_000, 100_000, 1)
    }) do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, remote)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "root")
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "root")
      channel.gets_packet(FXP_NAME, :long, 1, :long, 2,
        :string, "file1", :string, "-rw-rw-r-- 1 bob bob 100 Aug 1 file1", :long, 0x04, :long, 0100644,
        :string, "..", :string, "drwxr-xr-x 4 bob bob 136 Aug 1 ..", :long, 0x04, :long, 040755)
      channel.sends_packet(FXP_READDIR, :long, 2, :string, "root")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 1)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "root")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)

      channel.sends_packet(FXP_OPEN, :long, 4, :string, File.join(remote, "file1"), :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 4, :string, "f1")
      channel.sends_packet(FXP_READ, :long, 5, :string, "f1", :int64, 0, :long, 32_000)
      channel.gets_packet(FXP_DATA, :long, 5, :string, "f1")
      channel.sends_packet(FXP_READ, :long, 6, :string, "f1", :int64, 2, :long, 32_000)
      channel.gets_packet(FXP_STATUS, :long, 6, :long, 1)
      channel.sends_packet(FXP_CLOSE, :long, 7, :string, "f1")
      channel.gets_packet(FXP_STATUS, :long, 7, :long, 0)
    end

    file = StringIO.new
    File.expects(:directory?).with(local).returns(false)
    Dir.expects(:mkdir).with(local)
    File.expects(:open).with(File.join(local, "file1"), "wb").returns(file)

    downloader = nil
    assert_scripted_command do
      downloader = sftp.download(remote, local, :recursive => true)
    end

    assert_equal "f1", file.string
    assert_equal 1, downloader.peak_open_handles
  end

  private

    def prepare_limited_directory_tree(local, remote)
      expect_sftp_session(:server_version => 3, :extensions => {
        Net::SFTP::Limits::EXTENSION_NAME => limits_blob(100_000, 100_000, 2)
      }) do |channel|
        channel.sends_packet(FXP_OPENDIR, :long, 0, :string, remote)
        channel.gets_packet(FXP_HANDLE, :long, 0, :string, "root")
        channel.sends_packet(FXP_READDIR, :long, 1, :string, "root")
        channel.gets_packet(FXP_NAME, :long, 1, :long, 3,
          :string, "..", :string, "drwxr-xr-x 4 bob bob 136 Aug 1 ..", :long, 0x04, :long, 040755,
          :string, "subdir1", :string, "drwxr-xr-x 4 bob bob 136 Aug 1 subdir1", :long, 0x04, :long, 040755,
          :string, "file1", :string, "-rw-rw-r-- 1 bob bob 100 Aug 1 file1", :long, 0x04, :long, 0100644)
        channel.sends_packet(FXP_READDIR, :long, 2, :string, "root")
        channel.gets_packet(FXP_STATUS, :long, 2, :long, 1)
        # subdir1 must not open yet: file1 is also queued and opening the
        # directory would leave zero slots for the waiting file. Root is
        # read to EOF and closed first, freeing its slot.
        channel.sends_packet(FXP_CLOSE, :long, 3, :string, "root")
        channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)

        # Root's slot is free. subdir1 opens, and because opening it leaves
        # a slot available (used by the waiting file1), both proceed:
        # directory and file share the two-handle budget.
        channel.sends_packet(FXP_OPENDIR, :long, 4, :string, File.join(remote, "subdir1"))
        channel.sends_packet(FXP_OPEN, :long, 5, :string, File.join(remote, "file1"), :long, 0x01, :long, 0)

        channel.gets_packet(FXP_HANDLE, :long, 4, :string, "sub")
        channel.sends_packet(FXP_READDIR, :long, 6, :string, "sub")
        channel.gets_packet(FXP_HANDLE, :long, 5, :string, "f1")
        channel.sends_packet(FXP_READ, :long, 7, :string, "f1", :int64, 0, :long, 32_000)

        channel.gets_packet(FXP_NAME, :long, 6, :long, 2,
          :string, ".", :string, "drwxr-xr-x 4 bob bob 136 Aug 1 .", :long, 0x04, :long, 040755,
          :string, "file2", :string, "-rw-rw-r-- 1 bob bob 100 Aug 1 file2", :long, 0x04, :long, 0100644)
        # file2 cannot open yet: both budget slots are held by sub and f1.
        channel.sends_packet(FXP_READDIR, :long, 8, :string, "sub")
        channel.gets_packet(FXP_DATA, :long, 7, :string, "f1")
        channel.sends_packet(FXP_READ, :long, 9, :string, "f1", :int64, 2, :long, 32_000)
        channel.gets_packet(FXP_STATUS, :long, 8, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 10, :string, "sub")

        channel.gets_packet(FXP_STATUS, :long, 9, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 11, :string, "f1")
        channel.gets_packet(FXP_STATUS, :long, 10, :long, 0)
        # sub's slot frees: file2 opens while f1 is still open.
        channel.sends_packet(FXP_OPEN, :long, 12, :string, File.join(remote, "subdir1", "file2"), :long, 0x01, :long, 0)
        channel.gets_packet(FXP_STATUS, :long, 11, :long, 0)
        channel.gets_packet(FXP_HANDLE, :long, 12, :string, "f2")
        channel.sends_packet(FXP_READ, :long, 13, :string, "f2", :int64, 0, :long, 32_000)
        channel.gets_packet(FXP_DATA, :long, 13, :string, "f2")
        channel.sends_packet(FXP_READ, :long, 14, :string, "f2", :int64, 2, :long, 32_000)
        channel.gets_packet(FXP_STATUS, :long, 14, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 15, :string, "f2")
        channel.gets_packet(FXP_STATUS, :long, 15, :long, 0)
      end

      File.expects(:directory?).with(local).returns(false)
      File.expects(:directory?).with(File.join(local, "subdir1")).returns(false)
      Dir.expects(:mkdir).with(local)
      Dir.expects(:mkdir).with(File.join(local, "subdir1"))

      file1 = StringIO.new
      file2 = StringIO.new
      File.expects(:open).with(File.join(local, "file1"), "wb").returns(file1)
      File.expects(:open).with(File.join(local, "subdir1", "file2"), "wb").returns(file2)

      [file1, file2]
    end

    def expect_file_transfer(remote, text, opts={})
      expect_sftp_session :server_version => 3 do |channel|
        channel.sends_packet(FXP_OPEN, :long, 0, :string, remote, :long, 0x01, :long, 0)
        channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
        channel.sends_packet(FXP_READ, :long, 1, :string, "handle", :int64, 0, :long, 32_000)
        channel.gets_packet_in_two(opts[:fragment_len], FXP_DATA, :long, 1, :string, text)
        channel.sends_packet(FXP_READ, :long, 2, :string, "handle", :int64, text.bytesize, :long, 32_000)
        channel.gets_packet(FXP_STATUS, :long, 2, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
        channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      end
    end

    def prepare_large_file_download(local, remote, text, requested_chunk_size = FXP_DATA_CHUNK_SIZE)
      expect_sftp_session :server_version => 3 do |channel|
        channel.sends_packet(FXP_OPEN, :long, 0, :string, remote, :long, 0x01, :long, 0)
        channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
        offset = 0
        data_packet_count = (text.bytesize / FXP_DATA_CHUNK_SIZE.to_f).ceil
        data_packet_count.times do |n|
          payload = text[n*FXP_DATA_CHUNK_SIZE,FXP_DATA_CHUNK_SIZE]
          channel.sends_packet(FXP_READ, :long, n+1, :string, "handle", :int64, offset, :long, requested_chunk_size)
          offset += payload.bytesize
          channel.gets_packet(FXP_DATA, :long, n+1, :string, payload)
        end
        channel.sends_packet(FXP_READ, :long, data_packet_count + 1, :string, "handle", :int64, offset, :long, requested_chunk_size)
        channel.gets_packet(FXP_STATUS, :long, data_packet_count + 1, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, data_packet_count + 2, :string, "handle")
        channel.gets_packet(FXP_STATUS, :long, data_packet_count + 2, :long, 0)
      end

      file = StringIO.new
      File.stubs(:open).with(local, "wb").returns(file)

      return file
    end

    # 0:OPENDIR(remote) ->
    # <- 0:HANDLE("dir1")
    # 1:READDIR("dir1") ->
    # <- 1:NAME("..", ".", "subdir1", "file1")
    # 2:OPENDIR(remote/subdir1) ->
    # 3:OPEN(remote/file1) ->
    # 4:READDIR("dir1") ->
    # <- 2:HANDLE("dir2")
    # 5:READDIR("dir2") ->
    # <- 3:HANDLE("file1")
    # 6:READ("file1", 0, 32k) ->
    # <- 4:STATUS(1)
    # 7:CLOSE("dir1") ->
    # <- 5:NAME("..", ".", "file2")
    # 8:OPEN(remote/subdir1/file2) ->
    # 9:READDIR("dir2") ->
    # <- 6:DATA("blah blah blah")
    # 10:READ("file1", n, 32k)
    # <- 7:STATUS(0)
    # <- 8:HANDLE("file2")
    # 11:READ("file2", 0, 32k) ->
    # <- 9:STATUS(1)
    # 12:CLOSE("dir2") ->
    # <- 10:STATUS(1)
    # 13:CLOSE("file1") ->
    # <- 11:DATA("blah blah blah")
    # 14:READ("file2", n, 32k) ->
    # <- 12:STATUS(0)
    # <- 13:STATUS(0)
    # <- 14:STATUS(1)
    # 15:CLOSE("file2") ->
    # <- 15:STATUS(0)

    def prepare_directory_tree_download(local, remote)
      file1_contents = "contents of file1"
      file2_contents = "contents of file2"
      expect_sftp_session :server_version => 3 do |channel|
        channel.sends_packet(FXP_OPENDIR, :long, 0, :string, remote)
        channel.gets_packet(FXP_HANDLE, :long, 0, :string, "dir1")

        channel.sends_packet(FXP_READDIR, :long, 1, :string, "dir1")
        channel.gets_packet(FXP_NAME, :long, 1, :long, 4,
          :string, "..",      :string, "drwxr-xr-x  4 bob bob  136 Aug  1 ..", :long, 0x04, :long, 040755,
          :string, ".",       :string, "drwxr-xr-x  4 bob bob  136 Aug  1 .", :long, 0x04, :long, 040755,
          :string, "subdir1", :string, "drwxr-xr-x  4 bob bob  136 Aug  1 subdir1", :long, 0x04, :long, 040755,
          :string, "file1",   :string, "-rw-rw-r--  1 bob bob  100 Aug  1 file1", :long, 0x04, :long, 0100644)

        channel.sends_packet(FXP_OPENDIR, :long, 2, :string, File.join(remote, "subdir1"))
        channel.sends_packet(FXP_OPEN, :long, 3, :string, File.join(remote, "file1"), :long, 0x01, :long, 0)
        channel.sends_packet(FXP_READDIR, :long, 4, :string, "dir1")

        channel.gets_packet(FXP_HANDLE, :long, 2, :string, "dir2")
        channel.sends_packet(FXP_READDIR, :long, 5, :string, "dir2")

        channel.gets_packet(FXP_HANDLE, :long, 3, :string, "file1")
        channel.sends_packet(FXP_READ, :long, 6, :string, "file1", :int64, 0, :long, 32_000)

        channel.gets_packet(FXP_STATUS, :long, 4, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 7, :string, "dir1")

        channel.gets_packet(FXP_NAME, :long, 5, :long, 3,
          :string, "..",    :string, "drwxr-xr-x  4 bob bob  136 Aug  1 ..", :long, 0x04, :long, 040755,
          :string, ".",     :string, "drwxr-xr-x  4 bob bob  136 Aug  1 .", :long, 0x04, :long, 040755,
          :string, "file2", :string, "-rw-rw-r--  1 bob bob  100 Aug  1 file2", :long, 0x04, :long, 0100644)

        channel.sends_packet(FXP_OPEN, :long, 8, :string, File.join(remote, "subdir1", "file2"), :long, 0x01, :long, 0)
        channel.sends_packet(FXP_READDIR, :long, 9, :string, "dir2")

        channel.gets_packet(FXP_DATA, :long, 6, :string, file1_contents)
        channel.sends_packet(FXP_READ, :long, 10, :string, "file1", :int64, file1_contents.bytesize, :long, 32_000)

        channel.gets_packet(FXP_STATUS, :long, 7, :long, 0)
        channel.gets_packet(FXP_HANDLE, :long, 8, :string, "file2")
        channel.sends_packet(FXP_READ, :long, 11, :string, "file2", :int64, 0, :long, 32_000)

        channel.gets_packet(FXP_STATUS, :long, 9, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 12, :string, "dir2")

        channel.gets_packet(FXP_STATUS, :long, 10, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 13, :string, "file1")

        channel.gets_packet(FXP_DATA, :long, 11, :string, file2_contents)
        channel.sends_packet(FXP_READ, :long, 14, :string, "file2", :int64, file2_contents.bytesize, :long, 32_000)

        channel.gets_packet(FXP_STATUS, :long, 12, :long, 0)
        channel.gets_packet(FXP_STATUS, :long, 13, :long, 0)
        channel.gets_packet(FXP_STATUS, :long, 14, :long, 1)
        channel.sends_packet(FXP_CLOSE, :long, 15, :string, "file2")
        channel.gets_packet(FXP_STATUS, :long, 15, :long, 0)
      end

      File.expects(:directory?).with(local).returns(false)
      File.expects(:directory?).with(File.join(local, "subdir1")).returns(false)
      Dir.expects(:mkdir).with(local)
      Dir.expects(:mkdir).with(File.join(local, "subdir1"))

      file1 = StringIO.new
      file2 = StringIO.new
      File.expects(:open).with(File.join(local, "file1"), "wb").returns(file1)
      File.expects(:open).with(File.join(local, "subdir1", "file2"), "wb").returns(file2)

      [file1, file2]
    end
end
