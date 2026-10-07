require "common"

class LimitsUnitTest < Net::SFTP::TestCase
  def test_zero_values_use_documented_local_limits
    limits = Net::SFTP::Limits.new(0, 0, 0, 0)

    assert_equal Net::SFTP::Limits::DEFAULT_PACKET_LENGTH, limits.packet_length
    assert_equal Net::SFTP::Limits::DEFAULT_READ_LENGTH, limits.read_length
    assert_equal Net::SFTP::Limits::DEFAULT_WRITE_LENGTH, limits.write_length
    assert_equal Net::SFTP::Limits::DEFAULT_OPEN_HANDLES, limits.open_handles
  end

  def test_missing_extension_preserves_original_requested_sizes
    limits = Net::SFTP::Limits.default
    handle = "h" * 1_000

    assert_equal 32_000, limits.maximum_read_length
    assert_equal 32_000, limits.maximum_write_length(handle)
    assert_equal 16, limits.maximum_open_handles(16)
  end

  def test_read_length_allows_for_response_packet_overhead
    limits = Net::SFTP::Limits.new(100, 10_000, 10_000, 4)

    assert_equal 91, limits.maximum_read_length
  end

  def test_write_length_allows_for_handle_and_packet_overhead
    limits = Net::SFTP::Limits.new(100, 10_000, 10_000, 4)
    handle = "h" * 20

    assert_equal 59, limits.maximum_write_length(handle)
  end

  def test_open_handle_limit_never_exceeds_server_budget
    limits = Net::SFTP::Limits.new(100, 100, 100, 2)

    assert_equal 2, limits.maximum_open_handles(16)
  end
end
