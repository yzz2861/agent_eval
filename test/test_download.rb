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

  private

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
end
