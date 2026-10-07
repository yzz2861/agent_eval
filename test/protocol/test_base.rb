require 'common'

class Protocol::TestBase < Net::SFTP::TestCase
  include Net::SFTP::Constants

  def setup
    @base = Net::SFTP::Protocol::Base.new(stub('session', :logger => nil))
  end

  def test_parse_with_status_packet_should_delegate_to_parse_status_packet
    packet = stub('packet', :type => FXP_STATUS)
    @base.expects(:parse_status_packet).with(packet).returns(:result)
    assert_equal :result, @base.parse(packet)
  end

  def test_parse_with_handle_packet_should_delegate_to_parse_handle_packet
    packet = stub('packet', :type => FXP_HANDLE)
    @base.expects(:parse_handle_packet).with(packet).returns(:result)
    assert_equal :result, @base.parse(packet)
  end

  def test_parse_with_data_packet_should_delegate_to_parse_data_packet
    packet = stub('packet', :type => FXP_DATA)
    @base.expects(:parse_data_packet).with(packet).returns(:result)
    assert_equal :result, @base.parse(packet)
  end

  def test_parse_with_name_packet_should_delegate_to_parse_name_packet
    packet = stub('packet', :type => FXP_NAME)
    @base.expects(:parse_name_packet).with(packet).returns(:result)
    assert_equal :result, @base.parse(packet)
  end

  def test_parse_with_attrs_packet_should_delegate_to_parse_attrs_packet
    packet = stub('packet', :type => FXP_ATTRS)
    @base.expects(:parse_attrs_packet).with(packet).returns(:result)
    assert_equal :result, @base.parse(packet)
  end

  def test_parse_with_unknown_packet_should_raise_exception
    packet = stub('packet', :type => FXP_WRITE)
    assert_raises(NotImplementedError) { @base.parse(packet) }
  end

  def test_copy_data_should_send_extended_packet
    @base.instance_variable_set(:@request_id_counter, -1)
    @base.session.expects(:send_packet).with(
      FXP_EXTENDED,
      :long, 0,
      :string, "copy-data",
      :string, "source-handle",
      :string, "target-handle",
      :int64, 10,
      :int64, 20,
      :int64, 30)

    assert_equal 0, @base.copy_data("source-handle", "target-handle", 10, 20, 30)
  end

  def test_copy_data_with_zero_length_should_send_extended_packet_to_end_of_file
    @base.instance_variable_set(:@request_id_counter, -1)
    @base.session.expects(:send_packet).with(
      FXP_EXTENDED,
      :long, 0,
      :string, "copy-data",
      :string, "source-handle",
      :string, "target-handle",
      :int64, 10,
      :int64, 20,
      :int64, 0)

    assert_equal 0, @base.copy_data("source-handle", "target-handle", 10, 20, 0)
  end
end
