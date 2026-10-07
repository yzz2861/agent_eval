require "common"

class CopyDataTest < Net::SFTP::TestCase
  include Net::SFTP::Constants
  include Net::SFTP::Constants::Extensions
  include Net::SFTP::Constants::OpenFlags
  include Net::SFTP::Constants::PacketTypes
  include Net::SFTP::Constants::StatusCodes

  def test_session_remembers_advertised_copy_data_extension
    expect_sftp_session :extensions => { COPY_DATA => "" }

    assert_scripted do
      sftp.connect!
      assert sftp.copy_data_supported?
      assert_equal({ COPY_DATA => "" }, sftp.extensions)
    end
  end

  def test_copy_data_sends_extended_packet_and_returns_status
    expect_copied_range(nil, 0)

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")
        response = sftp.copy_data!("source", "destination", 100, 300, nil)
        assert response.ok?
      end
    end
  end

  def test_copy_data_sends_explicit_length
    expect_copied_range(20, 20)

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")
        response = sftp.copy_data!("source", "destination", 100, 300, 20)
        assert response.ok?
      end
    end
  end

  def test_copy_data_does_not_retry_after_server_error
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/source", "source", "r", 0)
      open_file(channel, "/destination", "destination", "w", 1)
      channel.sends_packet(FXP_EXTENDED,
        :long, 2,
        :string, COPY_DATA,
        :string, "source",
        :int64, 100,
        :int64, 20,
        :string, "destination",
        :int64, 300)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, FX_FAILURE)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")

        assert_raises(Net::SFTP::StatusException) do
          sftp.copy_data!("source", "destination", 100, 300, 20)
        end
      end
    end
  end

  def test_connection_loss_is_indeterminate_and_is_not_retried
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/source", "source", "r", 0)
      open_file(channel, "/destination", "destination", "w", 1)
      channel.sends_packet(FXP_EXTENDED,
        :long, 2,
        :string, COPY_DATA,
        :string, "source",
        :int64, 100,
        :int64, 0,
        :string, "destination",
        :int64, 300)
      channel.gets_close
      channel.sends_close
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")

        exception = assert_raises(Net::SFTP::IndeterminateStatusException) do
          sftp.copy_data!("source", "destination", 100, 300, nil)
        end
        assert exception.response.indeterminate?
        assert_equal FX_CONNECTION_LOST, exception.code
      end
    end
  end

  def test_close_removes_handle_from_session_registry
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/source", "source", "r", 0)
      channel.sends_packet(FXP_CLOSE, :long, 1, :string, "source")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, FX_OK)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        assert handles_include?(sftp, "source")
        sftp.close!("source")
        refute handles_include?(sftp, "source")
      end
    end
  end

  def test_handles_must_belong_to_this_session_and_refer_to_files
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/source", "source", "r", 0)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")

        assert_raises(ArgumentError) do
          sftp.copy_data!("foreign", "source", 0, 0, 1)
        end

        register_test_handle(sftp, "directory", "/directory", true)
        assert_raises(ArgumentError) do
          sftp.copy_data!("source", "directory", 0, 0, 1)
        end
      end
    end
  end

  def test_uint64_arguments_are_validated
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/source", "source", "r", 0)
      open_file(channel, "/destination", "destination", "w", 1)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")

        assert_raises(ArgumentError) { sftp.copy_data!("source", "destination", -1, 0, 1) }
        assert_raises(ArgumentError) { sftp.copy_data!("source", "destination", 0, 2 ** 64, 1) }
        assert_raises(ArgumentError) { sftp.copy_data!("source", "destination", 0, 0, 2 ** 64) }
        assert_raises(ArgumentError) { sftp.copy_data!("source", "destination", 2 ** 64 - 1, 0, 1) }
      end
    end
  end

  def test_same_file_overlap_is_rejected_by_default_and_can_be_explicitly_allowed
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/same", "first", "r", 0)
      open_file(channel, "/same", "second", "w", 1)
      channel.sends_packet(FXP_EXTENDED,
        :long, 2,
        :string, COPY_DATA,
        :string, "first",
        :int64, 0,
        :int64, 0,
        :string, "second",
        :int64, 5)
      channel.gets_packet(FXP_STATUS, :long, 2, :long, FX_OK)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/same", "r")
        sftp.open!("/same", "w")

        assert_raises(ArgumentError) do
          sftp.copy_data!("first", "second", 0, 4, 10)
        end

        response = sftp.copy_data!("first", "second", 0, 5, nil, :allow_overlap => true)
        assert response.ok?
      end
    end
  end

  def test_fallback_requires_explicit_opt_in
    expect_sftp_session

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        register_test_handle(sftp, "source", "/source", false)
        register_test_handle(sftp, "destination", "/destination", false)

        assert_raises(NotImplementedError) do
          sftp.copy_data!("source", "destination", 0, 0, nil)
        end
      end
    end
  end

  def test_asynchronous_copy_does_not_accept_fallback_or_read_size
    expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
      open_file(channel, "/source", "source", "r", 0)
      open_file(channel, "/destination", "destination", "w", 1)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")

        assert_raises(ArgumentError) do
          sftp.copy_data("source", "destination", 0, 0, nil, :fallback => true)
        end
        assert_raises(ArgumentError) do
          sftp.copy_data!("source", "destination", 0, 0, nil, :read_size => 1024)
        end
      end
    end
  end

  def test_fallback_uses_bounded_reads_writes_and_handles_short_reads
    expect_sftp_session :server_version => 3 do |channel|
      open_file(channel, "/source", "source", "r", 0, 3)
      open_file(channel, "/destination", "destination", "w", 1, 3)

      channel.sends_packet(FXP_READ, :long, 2, :string, "source", :int64, 10, :long, 4)
      channel.gets_packet(FXP_DATA, :long, 2, :string, "abcd")
      channel.sends_packet(FXP_WRITE, :long, 3, :string, "destination", :int64, 20, :string, "abcd")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, FX_OK)

      channel.sends_packet(FXP_READ, :long, 4, :string, "source", :int64, 14, :long, 4)
      channel.gets_packet(FXP_DATA, :long, 4, :string, "ef")
      channel.sends_packet(FXP_WRITE, :long, 5, :string, "destination", :int64, 24, :string, "ef")
      channel.gets_packet(FXP_STATUS, :long, 5, :long, FX_OK)

      channel.sends_packet(FXP_READ, :long, 6, :string, "source", :int64, 16, :long, 4)
      channel.gets_packet(FXP_STATUS, :long, 6, :long, FX_EOF)
    end

    assert_scripted do
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        sftp.open!("/source", "r")
        sftp.open!("/destination", "w")
        result = sftp.copy_data!("source", "destination", 10, 20, nil,
          :fallback => true, :read_size => 4)
        assert_equal 6, result
      end
    end
  end

  private

    def expect_copied_range(length_argument, wire_length)
      expect_sftp_session :extensions => { COPY_DATA => "" } do |channel|
        open_file(channel, "/source", "source", "r", 0)
        open_file(channel, "/destination", "destination", "w", 1)
        channel.sends_packet(FXP_EXTENDED,
          :long, 2,
          :string, COPY_DATA,
          :string, "source",
          :int64, 100,
          :int64, wire_length,
          :string, "destination",
          :int64, 300)
        channel.gets_packet(FXP_STATUS, :long, 2, :long, FX_OK)
      end
    end

    def open_file(channel, path, handle, mode, id, version=6)
      if version >= 5
        access, flags = open_arguments(mode)
        attrs = [:long, 0, :byte, 1]
        channel.sends_packet(FXP_OPEN, :long, id, :string, path, :long, access, :long, flags, *attrs)
      else
        flags = mode == "r" ? FV1::READ : FV1::WRITE | FV1::TRUNC | FV1::CREAT
        attrs = [:long, 0]
        channel.sends_packet(FXP_OPEN, :long, id, :string, path, :long, flags, *attrs)
      end

      channel.gets_packet(FXP_HANDLE, :long, id, :string, handle)
    end

    def open_arguments(mode)
      if mode == "r"
        [ACE::Mask::READ_DATA | ACE::Mask::READ_ATTRIBUTES, FV5::OPEN_EXISTING]
      else
        [ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES, FV5::CREATE_TRUNCATE]
      end
    end

    def handles_include?(session, handle)
      session.instance_variable_get(:@handles).key?(handle)
    end

  def register_test_handle(session, handle, path, directory)
    session.instance_variable_get(:@handles)[handle] =
      { :path => path, :directory => directory }
  end
end
