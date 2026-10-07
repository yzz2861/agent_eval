require 'common'
require 'protocol/02/test_base'

class Protocol::V03::TestBase < Protocol::V02::TestBase
  def test_version
    assert_equal 3, @base.version
  end

  undef test_readlink_should_raise_not_implemented_error
  undef test_symlink_should_raise_not_implemented_error
  undef test_copy_data_should_raise_not_implemented_error

  def test_readlink_should_send_readlink_packet
    @session.expects(:send_packet).with(FXP_READLINK, :long, 0, :string, "/path/to/link")
    assert_equal 0, @base.readlink("/path/to/link")
  end

  def test_symlink_should_send_symlink_packet
    @session.expects(:send_packet).with(FXP_SYMLINK, :long, 0, :string, "/path/to/link", :string, "/path/to/file")
    assert_equal 0, @base.symlink("/path/to/link", "/path/to/file")
  end

  def test_copy_data_should_send_extended_packet
    @session.expects(:send_packet).with(FXP_EXTENDED,
      :long, 0,
      :string, Extensions::COPY_DATA,
      :string, "source-handle",
      :int64, 100,
      :int64, 20,
      :string, "destination-handle",
      :int64, 300)
    assert_equal 0, @base.copy_data("source-handle", "destination-handle", 100, 300, 20)
  end

  def test_copy_data_to_end_should_send_zero_length
    @session.expects(:send_packet).with(FXP_EXTENDED,
      :long, 0,
      :string, Extensions::COPY_DATA,
      :string, "source-handle",
      :int64, 100,
      :int64, 0,
      :string, "destination-handle",
      :int64, 300)
    assert_equal 0, @base.copy_data("source-handle", "destination-handle", 100, 300, 0)
  end

  private

    def driver
      Net::SFTP::Protocol::V03::Base
    end
end
