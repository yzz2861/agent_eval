require "common"

class LimitsTest < Minitest::Test
  Limits = Net::SFTP::Limits

  def blob(version, read_limit, write_limit, open_handles)
    Net::SSH::Buffer.from(:long, version,
                          :int64, read_limit,
                          :int64, write_limit,
                          :int64, open_handles).to_s
  end

  def test_parse_extension_blob
    limits = Limits.parse(blob(1, 100, 200, 4))
    assert_equal 100, limits.max_read_bytes
    assert_equal 200, limits.max_write_bytes
    assert_equal 4, limits.max_open_handles
  end

  def test_parse_rejects_unknown_version
    assert_nil Limits.parse(blob(2, 100, 200, 4))
  end

  def test_parse_rejects_truncated_and_missing_blob
    assert_nil Limits.parse(nil)
    assert_nil Limits.parse("short")
    assert_nil Limits.parse(Net::SSH::Buffer.from(:long, 1, :int64, 100).to_s)
  end

  def test_zero_values_become_documented_local_caps
    limits = Limits.parse(blob(1, 0, 0, 0))
    assert_equal Limits::DEFAULT_MAX_READ_BYTES, limits.max_read_bytes
    assert_equal Limits::DEFAULT_MAX_WRITE_BYTES, limits.max_write_bytes
    assert_equal Limits::DEFAULT_MAX_OPEN_HANDLES, limits.max_open_handles
  end

  def test_read_length_leaves_room_for_reply_encoding
    limits = Limits.new(50, 1_000, 1_000)
    assert_equal 41, limits.read_length(32_000)
    assert_equal 10, limits.read_length(10)
  end

  def test_read_length_never_drops_below_one_byte
    limits = Limits.new(1, 1_000, 1_000)
    assert_equal 1, limits.read_length(32_000)
  end

  def test_write_length_accounts_for_handle_byte_length
    limits = Limits.new(1_000, 50, 1_000)
    assert_equal 19, limits.write_length(32_000, "x" * 10)
    handle = "x" * 20
    assert_equal 9, limits.write_length(32_000, handle)
  end

  def test_write_length_never_drops_below_one_byte
    limits = Limits.new(1_000, 22, 1_000)
    assert_equal 1, limits.write_length(32_000, "x" * 100)
  end
end

class LimitsSessionTest < Net::SFTP::TestCase
  def limits_blob(read_limit, write_limit, open_handles)
    Net::SSH::Buffer.from(:long, 1,
                          :int64, read_limit,
                          :int64, write_limit,
                          :int64, open_handles).to_s
  end

  def test_session_exposes_negotiated_limits_extension
    data = limits_blob(64, 64, 3)
    expect_sftp_session(:server_version => 3, :extensions => {
      Net::SFTP::Limits::EXTENSION_NAME => data,
      "other@example.com" => "whatever"
    })

    assert_scripted do
      sftp.connect!
    end

    assert_equal data, sftp.extensions[Net::SFTP::Limits::EXTENSION_NAME]
    assert_equal "whatever", sftp.extensions["other@example.com"]
    assert_kind_of Net::SFTP::Limits, sftp.limits
    assert_equal 64, sftp.limits.max_read_bytes
    assert_equal 64, sftp.limits.max_write_bytes
    assert_equal 3, sftp.limits.max_open_handles
  end

  def test_session_without_extension_has_no_limits_and_keeps_old_behavior
    expect_sftp_session(:server_version => 3)
    assert_scripted do
      sftp.connect!
    end

    assert_equal({}, sftp.extensions)
    assert_nil sftp.limits
  end

  def test_session_ignores_malformed_limits_extension
    expect_sftp_session(:server_version => 3, :extensions => {
      Net::SFTP::Limits::EXTENSION_NAME => "bogus"
    })
    assert_scripted do
      sftp.connect!
    end

    assert_nil sftp.limits
  end
end
