require "common"
require "digest"

class ChecksumDownloadTest < Net::SFTP::TestCase
  REMOTE = "/path/to/remote"

  def test_check_file_request_and_reply_follow_extension_wire_format
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_EXTENDED,
        :long, 0,
        :string, "check-file",
        :string, REMOTE,
        :string, "sha256,sha1",
        :int64, 12,
        :int64, 56,
        :int64, 34)
      channel.gets_packet(FXP_EXTENDED_REPLY,
        :long, 0,
        :string, "sha256",
        :int64, 12,
        :int64, 34,
        :int64, 11,
        :long, 2,
        :string, "a" * 32,
        :string, "b" * 10)
    end

    assert_scripted_command do
      response = sftp.check_file!(REMOTE, "sha256,sha1", 12, 34, 56)
      assert_equal "sha256", response[:algorithm]
      assert_equal 12, response[:offset]
      assert_equal 34, response[:end_offset]
      assert_equal 11, response[:block_size]
      assert_equal ["a" * 32, "b" * 10], response[:checksums]
    end
  end

  def test_downloads_only_blocks_whose_checksums_differ_and_verifies_whole_file
    local = StringIO.new("aaaa2222")
    old_first = "AAAA"
    unchanged = "2222"
    final_data = old_first + unchanged

    expect_checksum_download(final_data, [[0, old_first.bytesize], [4, unchanged.bytesize]],
      differing: { 0 => old_first },
      final_data: final_data)

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, local, :algorithms => "sha256", :block_size => 4)
    end

    assert result.ok?
    assert_equal final_data, local.string
    assert_equal [[0, 4]], result.read_ranges
  end

  def test_remote_rewrite_during_final_checksum_returns_retry_without_success
    local = StringIO.new("aaaa2222")
    original_data = "AAAA2222"
    rewritten_data = "BBBB2222"

    expect_checksum_download(original_data, [[0, 4], [4, 4]],
      differing: { 0 => "AAAA" },
      final_data: rewritten_data)

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, local, :algorithms => "sha256", :block_size => 4)
    end

    assert result.retry?
    assert_equal :final_checksum_mismatch, result.reason
    assert_equal "AAAA2222", local.string
    assert_equal [[0, 4]], result.read_ranges
  end

  def test_zero_length_file_uses_final_checksum_without_a_read
    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
        :string, "sha512,sha384,sha256,sha1,md5", :int64, 0, :int64, 0, :int64, 0)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 2, :string, "sha256",
        :int64, 0, :int64, 0, :int64, 0, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 3, :string, "check-file", :string, REMOTE,
        :string, "sha512,sha384,sha256,sha1,md5", :int64, 0, :int64, 0, :int64, 0)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 3, :string, "sha256",
        :int64, 0, :int64, 0, :int64, 0, :long, 0)
      channel.sends_packet(FXP_STAT, :long, 4, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 4, :long, 1, :int64, 0)
      channel.sends_packet(FXP_CLOSE, :long, 5, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 5, :long, 0)
    end

    local = StringIO.new("")
    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, local)
    end

    assert result.ok?
    assert_equal [], result.read_ranges
  end

  def test_identical_blocks_send_no_reads_still_verify_the_whole_file
    data = "AAAA2222"
    checksums = [Digest::SHA256.digest(data[0, 4]), Digest::SHA256.digest(data[4, 4])]
    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, 8)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
        :string, "sha256", :int64, 0, :int64, 4, :int64, 8)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 2, :string, "sha256",
        :int64, 0, :int64, 8, :int64, 4, :long, 2, :string, checksums[0], :string, checksums[1])
      channel.sends_packet(FXP_EXTENDED, :long, 3, :string, "check-file", :string, REMOTE,
        :string, "sha256", :int64, 0, :int64, 4, :int64, 8)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 3, :string, "sha256",
        :int64, 0, :int64, 8, :int64, 4, :long, 2,
        :string, checksums[0], :string, checksums[1])
      channel.sends_packet(FXP_STAT, :long, 4, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 4, :long, 1, :int64, 8)
      channel.sends_packet(FXP_CLOSE, :long, 5, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 5, :long, 0)
    end

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, StringIO.new(data), :algorithms => "sha256", :block_size => 4)
    end

    assert result.ok?
    assert_equal [], result.read_ranges
  end

  def test_blocks_crossing_old_local_length_are_always_downloaded
    data = "ABCDEFGHIJ"
    local = StringIO.new("ABCDX")

    expect_checksum_download(data, [[0, 4], [4, 4], [8, 2]],
      differing: { 4 => "EFGH", 8 => "IJ" },
      final_data: data)

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, local, :algorithms => "sha256", :block_size => 4)
    end

    assert result.ok?
    assert_equal data, local.string
    assert_equal [[4, 4], [8, 2]], result.read_ranges
  end

  def test_unknown_server_algorithm_is_not_replaced_by_client_algorithm
    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, 8)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
        :string, "sha256", :int64, 0, :int64, 4, :int64, 8)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 2, :string, "rot13",
        :int64, 0, :int64, 8, :int64, 4, :long, 2,
        :string, "x", :string, "y")
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted_command do
      sftp.checksum_download!(REMOTE, StringIO.new("aaaaaaaa"),
        :algorithms => "sha256", :block_size => 4).tap { |operation| result = operation }
    end

    assert_equal :unsupported_algorithm, result.status
    assert_equal [], result.read_ranges
  end

  def test_local_length_change_during_block_comparison_returns_dedicated_status
    mutable_local = Object.new
    checks = 0
    mutable_local.define_singleton_method(:read) do |length|
      "a" * length
    end
    mutable_local.define_singleton_method(:write) { |data| data.bytesize }
    mutable_local.define_singleton_method(:seek) { |*| }
    mutable_local.define_singleton_method(:truncate) { |*| }
    mutable_local.define_singleton_method(:size) do
      checks += 1
      checks == 1 ? 8 : 9
    end

    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, 8)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
        :string, "sha256", :int64, 0, :int64, 4, :int64, 8)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 2, :string, "sha256",
        :int64, 0, :int64, 8, :int64, 4, :long, 2,
        :string, "a" * 32, :string, "b" * 32)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, mutable_local,
        :algorithms => "sha256", :block_size => 4)
    end

    assert_equal :local_length_changed, result.status
    assert_equal [], result.read_ranges
  end

  def test_wrong_checksum_count_is_invalid
    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, 8)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
        :string, "sha256", :int64, 0, :int64, 4, :int64, 8)
      channel.gets_packet(FXP_EXTENDED_REPLY, :long, 2, :string, "sha256",
        :int64, 0, :int64, 8, :int64, 4, :long, 1,
        :string, Digest::SHA256.digest("a" * 8))
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted_command do
      sftp.checksum_download!(REMOTE, StringIO.new("aaaaaaaa"),
        :algorithms => "sha256", :block_size => 4).tap { |operation| result = operation }
    end

    assert_equal :invalid_checksum_response, result.status
    assert_equal [], result.read_ranges
  end

  def test_missing_extension_returns_extension_unavailable
    expect_sftp_session :server_version => 3
    result = nil
    assert_scripted_command do
      sftp.connect!
      operation = sftp.checksum_download(REMOTE, StringIO.new("x"))
      sftp.loop
      result = operation
    end
    assert_equal :extension_unavailable, result.status
  end

  def test_check_file_unsupported_after_negotiation_returns_extension_unavailable
    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, 8)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
        :string, "sha512,sha384,sha256,sha1,md5", :int64, 0, :int64, 0, :int64, 8)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 8)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, StringIO.new("xxxxxxxx"))
    end

    assert_equal :extension_unavailable, result.status
  end

  def test_read_only_local_returns_read_only
    expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" }
    local = Object.new
    def local.read(length = nil); ""; end

    result = nil
    assert_scripted_command do
      result = sftp.checksum_download!(REMOTE, local)
    end

    assert_equal :read_only, result.status
  end

  private

    def expect_checksum_download(data, ranges, differing:, final_data:)
      block_size = ranges.first[1]
      checksums = ranges.map { |range| Digest::SHA256.digest(data[range[0], range[1]]) }
      final_checksums = ranges.map { |range| Digest::SHA256.digest(final_data[range[0], range[1]]) }

      expect_sftp_session :server_version => 3, :extensions => { "check-file" => "" } do |channel|
        channel.sends_packet(FXP_OPEN, :long, 0, :string, REMOTE, :long, 0x01, :long, 0)
        channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
        channel.sends_packet(FXP_STAT, :long, 1, :string, REMOTE)
        channel.gets_packet(FXP_ATTRS, :long, 1, :long, 1, :int64, data.bytesize)

        channel.sends_packet(FXP_EXTENDED, :long, 2, :string, "check-file", :string, REMOTE,
          :string, "sha256", :int64, 0, :int64, block_size, :int64, data.bytesize)
        reply = [FXP_EXTENDED_REPLY, :long, 2, :string, "sha256",
          :int64, 0, :int64, data.bytesize, :int64, block_size, :long, checksums.length]
        checksums.each { |checksum| reply.concat([:string, checksum]) }
        channel.gets_packet(*reply)

        read_id = 3
        differing.each do |offset, chunk|
          channel.sends_packet(FXP_READ, :long, read_id, :string, "handle",
            :int64, offset, :long, chunk.bytesize)
          channel.gets_packet(FXP_DATA, :long, read_id, :string, chunk)
          read_id += 1
        end

        next_id = 3 + differing.length
        channel.sends_packet(FXP_STAT, :long, next_id, :string, REMOTE)
        channel.gets_packet(FXP_ATTRS, :long, next_id, :long, 1, :int64, data.bytesize)
        channel.sends_packet(FXP_EXTENDED, :long, next_id + 1, :string, "check-file", :string, REMOTE,
          :string, "sha256", :int64, 0, :int64, block_size, :int64, data.bytesize)
        final_reply = [FXP_EXTENDED_REPLY, :long, next_id + 1, :string, "sha256",
          :int64, 0, :int64, data.bytesize, :int64, block_size, :long, final_checksums.length]
        final_checksums.each { |checksum| final_reply.concat([:string, checksum]) }
        channel.gets_packet(*final_reply)
        if final_data == data
          channel.sends_packet(FXP_STAT, :long, next_id + 2, :string, REMOTE)
          channel.gets_packet(FXP_ATTRS, :long, next_id + 2, :long, 1, :int64, data.bytesize)
          close_id = next_id + 3
        else
          close_id = next_id + 2
        end
        channel.sends_packet(FXP_CLOSE, :long, close_id, :string, "handle")
        channel.gets_packet(FXP_STATUS, :long, close_id, :long, 0)
      end
    end
end
