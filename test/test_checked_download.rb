require "common"
require "digest"
require "tmpdir"
require "fileutils"

class CheckedDownloadTest < Net::SFTP::TestCase
  REMOTE = "/path/to/remote".freeze
  ALGORITHMS = "sha256,sha384,sha512,sha1,md5".freeze

  def setup
    @tempdir = Dir.mktmpdir
    @local = File.join(@tempdir, "local.txt")
    self.class.recorded_reads = []
  end

  def teardown
    FileUtils.rm_rf(@tempdir)
    self.class.recorded_reads = nil
  end

  # The [offset, length] pairs of every FXP_READ packet sent so far.
  def reads
    self.class.recorded_reads
  end

  # When assigned an array, every FXP_READ packet actually sent by the
  # client is appended to it as an [offset, length] pair (see
  # ReadRangeRecorder at the bottom of this file).
  class << self
    attr_accessor :recorded_reads
  end

  def test_download_checked_should_fetch_only_differing_blocks
    remote_content = "aaaabbbbccccddddeeee"
    write_local("aaaaXXXXccccdddd")
    expect_checked_session do |channel|
      expect_stat(channel, 0, remote_content.bytesize)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", block_digests(remote_content, 4))
      expect_read(channel, 3, 4, 4, "bbbb")
      expect_read(channel, 4, 16, 4, "eeee")
      expect_check_file(channel, 5, "sha256", 0, 0, 0, "sha256", [Digest::SHA256.digest(remote_content)])
      expect_close(channel, 6)
    end

    result = nil
    assert_scripted_command { result = sftp.download_checked(REMOTE, @local, :block_size => 4) }

    assert result.ok?, "expected :ok, got #{result.status.inspect} (#{result.reason.inspect})"
    assert_equal "sha256", result.algorithm
    assert_equal 4, result.block_size
    assert_equal 5, result.block_count
    assert_equal 2, result.downloaded_blocks
    assert_equal 8, result.downloaded_bytes
    assert_equal [[4, 4], [16, 4]], reads
    assert_equal remote_content, File.binread(@local)
    assert sftp.extensions.key?("check-file")
  end

  def test_download_checked_should_succeed_without_reads_when_already_in_sync
    remote_content = "aaaabbbbccccddddeeee"
    write_local(remote_content)

    expect_checked_session do |channel|
      expect_stat(channel, 0, remote_content.bytesize)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", block_digests(remote_content, 4))
      expect_check_file(channel, 3, "sha256", 0, 0, 0, "sha256", [Digest::SHA256.digest(remote_content)])
      expect_close(channel, 4)
    end

    result = nil
    assert_scripted_command { result = sftp.download_checked(REMOTE, @local, :block_size => 4) }

    assert result.ok?
    assert_equal 0, result.downloaded_blocks
    assert_equal [], reads
    assert_equal remote_content, File.binread(@local)
  end

  def test_download_checked_should_report_retry_when_remote_changes_during_verification
    remote_content = "aaaabbbbccccddddeeee"
    write_local(remote_content)

    expect_checked_session do |channel|
      expect_stat(channel, 0, remote_content.bytesize)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", block_digests(remote_content, 4))
      # the remote file is rewritten between the block comparison and the
      # final whole-content verification; matching sizes prove nothing
      expect_check_file(channel, 3, "sha256", 0, 0, 0, "sha256", [Digest::SHA256.digest("ffffgggghhhhiiiijjjj")])
      expect_close(channel, 4)
    end

    result = nil
    assert_scripted_command { result = sftp.download_checked(REMOTE, @local, :block_size => 4) }

    assert result.retry?, "expected :retry, got #{result.status.inspect}"
    assert_equal :remote_changed, result.reason
    assert_equal 0, result.downloaded_blocks
    assert_equal [], reads
    assert_equal remote_content, File.binread(@local)
  end

  def test_download_checked_should_report_retry_when_last_block_reads_short
    remote_content = "aaaabbbbccccddddeeee"
    write_local("aaaabbbbccccdddd")

    expect_checked_session do |channel|
      expect_stat(channel, 0, remote_content.bytesize)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", block_digests(remote_content, 4))
      # the remote file shrank after the block comparison, so the final
      # block cannot be read in full
      channel.sends_packet(FXP_READ, :long, 3, :string, "handle", :int64, 16, :long, 4)
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 1)
      expect_close(channel, 4)
    end

    result = nil
    assert_scripted_command { result = sftp.download_checked(REMOTE, @local, :block_size => 4) }

    assert result.retry?
    assert_equal :remote_changed, result.reason
    assert_equal [[16, 4]], reads
  end

  def test_download_checked_should_report_retry_when_local_file_changes_length
    remote_content = "aaaabbbbccccddddeeee"
    write_local("aaaaXXXXccccdddd")
    File.stubs(:size).with(@local).returns(30)

    expect_checked_session do |channel|
      expect_stat(channel, 0, remote_content.bytesize)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", block_digests(remote_content, 4))
      expect_read(channel, 3, 4, 4, "bbbb")
      expect_read(channel, 4, 16, 4, "eeee")
      expect_close(channel, 5)
    end

    result = nil
    assert_scripted_command { result = sftp.download_checked(REMOTE, @local, :block_size => 4) }

    assert result.retry?
    assert_equal :local_changed, result.reason
  end

  def test_download_checked_should_raise_when_check_file_extension_is_unavailable
    write_local("anything")

    expect_checked_session({})

    assert_scripted_command do
      assert_raises(Net::SFTP::Exception) { sftp.download_checked(REMOTE, @local) }
    end
  end

  def test_download_checked_should_raise_when_local_file_is_read_only
    write_local("anything")
    FileUtils.chmod(0444, @local)

    expect_checked_session

    assert_scripted_command do
      assert_raises(ArgumentError) { sftp.download_checked(REMOTE, @local) }
    end
  end

  def test_download_checked_should_raise_when_server_selects_unknown_algorithm
    write_local("aaaabbbbccccddddeeee")

    expect_checked_session do |channel|
      expect_stat(channel, 0, 20)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "tiger", [])
      expect_close(channel, 3)
    end

    assert_scripted_command do
      error = assert_raises(Net::SFTP::Exception) { sftp.download_checked(REMOTE, @local, :block_size => 4) }
      assert_match(/tiger/, error.message)
    end
  end

  def test_download_checked_should_raise_when_hash_count_does_not_match_block_layout
    remote_content = "aaaabbbbccccddddeeee"
    write_local(remote_content)

    expect_checked_session do |channel|
      expect_stat(channel, 0, 20)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", block_digests(remote_content, 4).first(4))
      expect_close(channel, 3)
    end

    assert_scripted_command do
      assert_raises(Net::SFTP::Exception) { sftp.download_checked(REMOTE, @local, :block_size => 4) }
    end
  end

  def test_download_checked_should_raise_when_digest_length_does_not_match_algorithm
    remote_content = "aaaabbbbccccddddeeee"
    write_local(remote_content)

    expect_checked_session do |channel|
      expect_stat(channel, 0, 20)
      expect_open(channel, 1)
      expect_check_file(channel, 2, ALGORITHMS, 0, 0, 4, "sha256", Array.new(5) { Digest::SHA1.digest("x") })
      expect_close(channel, 3)
    end

    assert_scripted_command do
      assert_raises(Net::SFTP::Exception) { sftp.download_checked(REMOTE, @local, :block_size => 4) }
    end
  end

  private

    def write_local(content)
      File.open(@local, "wb") { |file| file.write(content) }
    end

    def block_digests(content, block_size)
      content.scan(/.{1,#{block_size}}/m).map { |block| Digest::SHA256.digest(block) }
    end

    def expect_checked_session(extensions={ "check-file" => "" })
      story do |session|
        channel = session.opens_channel
        channel.sends_subsystem("sftp")
        channel.sends_packet(FXP_INIT, :long, Net::SFTP::Session::HIGHEST_PROTOCOL_VERSION_SUPPORTED)
        version = [:long, 3]
        extensions.each { |name, data| version += [:string, name, :string, data] }
        channel.gets_packet(FXP_VERSION, *version)
        yield channel if block_given?
      end
    end

    def expect_stat(channel, id, size)
      channel.sends_packet(FXP_STAT, :long, id, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, id, :long, 0x01, :int64, size)
    end

    def expect_open(channel, id)
      channel.sends_packet(FXP_OPEN, :long, id, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, id, :string, "handle")
    end

    def expect_check_file(channel, id, offered, start, length, block_size, algorithm, hashes)
      channel.sends_packet(FXP_EXTENDED, :long, id, :string, "check-file", :string, "handle",
        :string, offered, :int64, start, :int64, length, :long, block_size)
      reply = [FXP_EXTENDED_REPLY, :long, id, :string, algorithm]
      hashes.each { |hash| reply += [:string, hash] }
      channel.gets_packet(*reply)
    end

    def expect_read(channel, id, offset, length, data)
      channel.sends_packet(FXP_READ, :long, id, :string, "handle", :int64, offset, :long, length)
      channel.gets_packet(FXP_DATA, :long, id, :string, data)
    end

    def expect_close(channel, id)
      channel.sends_packet(FXP_CLOSE, :long, id, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, id, :long, 0)
    end
end

# A protocol stub hook that observes the packets the client actually sends
# on the wire and records the [offset, length] range of every FXP_READ
# request into CheckedDownloadTest.recorded_reads (when set).
module ReadRangeRecorder
  def send_data(data)
    if (reads = CheckedDownloadTest.recorded_reads)
      buffer = Net::SSH::Buffer.new(data.dup)
      buffer.read_long # packet length
      if buffer.read_byte == Net::SFTP::Constants::PacketTypes::FXP_READ
        buffer.read_long   # request id
        buffer.read_string # handle
        reads << [buffer.read_int64, buffer.read_long]
      end
    end
    super
  end
end

Net::SSH::Connection::Channel.prepend(ReadRangeRecorder)
