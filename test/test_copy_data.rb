require "common"

class CopyDataTest < Net::SFTP::TestCase
  include Net::SFTP::Constants
  include Net::SFTP::Constants::OpenFlags
  include Net::SFTP::Constants::PacketTypes
  include Net::SFTP::Constants::StatusCodes

  def setup
    @sftp = nil
    @connection = nil
    @transport = nil
    @socket = nil
    super
  end

  def test_version_negotiation_retains_copy_data_extension
    expect_copy_data_session do |channel|
    end

    assert_scripted { sftp.connect! }
    assert_equal "1", sftp.extensions["copy-data"]
    assert sftp.supports_copy_data?
  end

  def test_copy_data_sends_explicit_range
    opened_handles do |channel|
      channel.sends_packet(FXP_EXTENDED, :long, 2,
        :string, "copy-data",
        :string, "source",
        :string, "target",
        :int64, 10,
        :int64, 20,
        :int64, 30)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    response = nil
    assert_scripted do
      sftp.connect!
      open_copy_handles!
      response = sftp.copy_data!("source", "target", 10, 20, 30)
    end

    assert response.ok?
    assert response.determinate?
  end

  def test_copy_data_with_nil_length_sends_zero_to_request_end_of_file
    opened_handles do |channel|
      channel.sends_packet(FXP_EXTENDED, :long, 2,
        :string, "copy-data",
        :string, "source",
        :string, "target",
        :int64, 10,
        :int64, 20,
        :int64, 0)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    assert_scripted do
      sftp.connect!
      open_copy_handles!
      assert sftp.copy_data!("source", "target", 10, 20).ok?
    end
  end

  def test_server_error_is_definitive_and_does_not_fallback
    opened_handles do |channel|
      channel.sends_packet(FXP_EXTENDED, :long, 2,
        :string, "copy-data", :string, "source", :string, "target",
        :int64, 10, :int64, 20, :int64, 30)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, FX_FAILURE)
    end

    error = nil
    assert_scripted do
      sftp.connect!
      open_copy_handles!
      error = assert_raises(Net::SFTP::StatusException) do
        sftp.copy_data!("source", "target", 10, 20, 30, :fallback => true)
      end
    end

    assert_equal FX_FAILURE, error.code
    assert error.determinate?
  end

  def test_connection_loss_after_request_is_indeterminate_and_not_retried
    opened_handles do |channel|
      channel.sends_packet(FXP_EXTENDED, :long, 2,
        :string, "copy-data", :string, "source", :string, "target",
        :int64, 10, :int64, 20, :int64, 30)
      channel.gets_close
      channel.sends_close
    end

    response = nil
    assert_scripted do
      sftp.connect!
      open_copy_handles!
      request = sftp.copy_data("source", "target", 10, 20, 30)
      request.wait
      response = request.response
    end

    assert_equal FX_CONNECTION_LOST, response.code
    refute response.determinate?
  end

  def test_fallback_uses_bounded_reads_and_writes
    opened_handles(extension: false) do |channel|
      channel.sends_packet(FXP_READ, :long, 2, :string, "source", :int64, 10, :long, 4)
      channel.gets_packet(FXP_DATA, :long, 2, :string, "abcd")
      channel.sends_packet(FXP_WRITE, :long, 3, :string, "target", :int64, 20, :string, "abcd")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.sends_packet(FXP_READ, :long, 4, :string, "source", :int64, 14, :long, 4)
      channel.gets_packet(FXP_STATUS, :long, 4, :long, FX_EOF)
    end

    response = nil
    assert_scripted do
      sftp.connect!
      open_copy_handles!
      response = sftp.copy_data!("source", "target", 10, 20, nil,
        :fallback => true, :read_size => 4)
    end

    assert response.ok?
    assert_equal 4, response[:bytes_copied]
  end

  def test_fallback_rejects_short_read_for_explicit_length
    opened_handles(extension: false) do |channel|
      channel.sends_packet(FXP_READ, :long, 2, :string, "source", :int64, 10, :long, 5)
      channel.gets_packet(FXP_DATA, :long, 2, :string, "abc")
    end

    assert_scripted do
      sftp.connect!
      open_copy_handles!
      assert_raises(EOFError) do
        sftp.copy_data!("source", "target", 10, 20, 5, :fallback => true)
      end
    end
  end

  def test_fallback_allows_non_overlapping_ranges_in_same_file
    opened_handles(extension: false, source_path: "/same", target_path: "/same",
                   source_handle: "same", target_handle: "same") do |channel|
      channel.sends_packet(FXP_READ, :long, 1, :string, "same", :int64, 0, :long, 4)
      channel.gets_packet(FXP_DATA, :long, 1, :string, "abcd")
      channel.sends_packet(FXP_WRITE, :long, 2, :string, "same", :int64, 10, :string, "abcd")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    response = nil
    assert_scripted do
      sftp.connect!
      sftp.open!("/same", "r+")
      response = sftp.copy_data!("same", "same", 0, 10, 4,
        :fallback => true, :read_size => 4)
    end

    assert_equal 4, response[:bytes_copied]
  end

  def test_fallback_still_rejects_overlapping_same_file_range
    opened_handles(extension: false, source_path: "/same", target_path: "/same",
                   source_handle: "same", target_handle: "same") do
    end

    assert_scripted do
      sftp.connect!
      sftp.open!("/same", "r+")
      assert_raises(ArgumentError) do
        sftp.copy_data!("same", "same", 0, 2, 4,
          :fallback => true, :allow_overlap => true)
      end
    end
  end

  def test_unsupported_native_response_falls_back_only_when_requested
    opened_handles do |channel|
      channel.sends_packet(FXP_EXTENDED, :long, 2,
        :string, "copy-data", :string, "source", :string, "target",
        :int64, 10, :int64, 20, :int64, 30)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, FX_OP_UNSUPPORTED)
      channel.sends_packet(FXP_READ, :long, 3, :string, "source", :int64, 10, :long, 30)
      channel.gets_packet(FXP_DATA, :long, 3, :string, "x" * 30)
      channel.sends_packet(FXP_WRITE, :long, 4, :string, "target", :int64, 20, :string, "x" * 30)
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
    end

    response = nil
    assert_scripted do
      sftp.connect!
      open_copy_handles!
      response = sftp.copy_data!("source", "target", 10, 20, 30, :fallback => true)
    end

    assert_equal 30, response[:bytes_copied]
  end

  def test_same_handle_overlap_is_rejected_by_default
    opened_handles(source_path: "/same", target_path: "/same",
                   source_handle: "same", target_handle: "same") do
    end

    assert_scripted do
      sftp.connect!
      sftp.open!("/same", "r+")
      assert_raises(ArgumentError) do
        sftp.copy_data!("same", "same", 10, 20, 20)
      end
    end
  end

  def test_same_handle_non_overlapping_ranges_are_allowed
    opened_handles(source_path: "/same", target_path: "/same",
                   source_handle: "same", target_handle: "same") do |channel|
      channel.sends_packet(FXP_EXTENDED, :long, 1,
        :string, "copy-data", :string, "same", :string, "same",
        :int64, 0, :int64, 10, :int64, 5)
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
    end

    assert_scripted do
      sftp.connect!
      sftp.open!("/same", "r+")
      assert sftp.copy_data!("same", "same", 0, 10, 5).ok?
    end
  end

  def test_unknown_handle_is_rejected
    opened_handles do
    end

    assert_scripted do
      sftp.connect!
      open_copy_handles!
      assert_raises(ArgumentError) do
        sftp.copy_data!("source", "foreign", 0, 0, 1)
      end
    end
  end

  def test_uint64_parameters_are_validated
    opened_handles do
    end

    assert_scripted do
      sftp.connect!
      open_copy_handles!
      assert_raises(ArgumentError) { sftp.copy_data!("source", "target", -1, 0, 1) }
      assert_raises(ArgumentError) { sftp.copy_data!("source", "target", 0, -1, 1) }
      assert_raises(ArgumentError) { sftp.copy_data!("source", "target", 0, 0, 2**64) }
    end
  end

  def test_successful_close_removes_handle_registration
    opened_handles do |channel|
      channel.sends_packet(FXP_CLOSE, :long, 2, :string, "source")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    handles = nil
    assert_scripted do
      sftp.connect!
      open_copy_handles!
      handles = sftp.instance_variable_get(:@handles)
      assert handles.key?("source")
      sftp.close!("source")
    end

    refute handles.key?("source")
  end

  private

    def expect_copy_data_session(extension: true)
      story do |session|
        channel = session.opens_channel
        channel.sends_subsystem("sftp")
        channel.sends_packet(FXP_INIT, :long, Net::SFTP::Session::HIGHEST_PROTOCOL_VERSION_SUPPORTED)
        args = [:long, 3]
        args += [:string, "copy-data", :string, "1"] if extension
        channel.gets_packet(FXP_VERSION, *args)
        yield channel
      end
    end

    def opened_handles(extension: true,
                       source_path: "/source", target_path: "/target",
                       source_handle: "source", target_handle: "target")
      expect_copy_data_session(extension: extension) do |channel|
        if source_path == target_path && source_handle == target_handle
          channel.sends_packet(FXP_OPEN, :long, 0, :string, source_path,
            :long, FV1::READ | FV1::WRITE,
            :raw, Net::SFTP::Protocol::V01::Attributes.new.to_s)
          channel.gets_packet(FXP_HANDLE, :long, 0, :string, source_handle)
        else
          channel.sends_packet(FXP_OPEN, :long, 0, :string, source_path,
            :long, FV1::READ, :raw, Net::SFTP::Protocol::V01::Attributes.new.to_s)
          channel.gets_packet(FXP_HANDLE, :long, 0, :string, source_handle)
          channel.sends_packet(FXP_OPEN, :long, 1, :string, target_path,
            :long, FV1::WRITE | FV1::CREAT | FV1::TRUNC,
            :raw, Net::SFTP::Protocol::V01::Attributes.new.to_s)
          channel.gets_packet(FXP_HANDLE, :long, 1, :string, target_handle)
        end
        yield channel
      end
    end

    def open_copy_handles!
      sftp.open!("/source", "r")
      sftp.open!("/target", "w")
    end
end
