require "common"

class FileFactoryTest < Net::SFTP::TestCase
  def setup
    @sftp = stub('sftp')
    @factory = Net::SFTP::Operations::FileFactory.new(@sftp)
  end

  def test_open_with_block_should_yield_and_close_handle
    @sftp.expects(:open!).with("/path/to/remote", "r", :permissions => nil).returns("handle")
    @sftp.expects(:close!).with("handle")

    called = false
    @factory.open("/path/to/remote") do |f|
      called = true
      assert_instance_of Net::SFTP::Operations::File, f
    end

    assert called
  end

  def test_open_with_block_should_close_file_even_if_exception_is_raised
    @sftp.expects(:open!).with("/path/to/remote", "r", :permissions => nil).returns("handle")
    @sftp.expects(:close!).with("handle")

    assert_raises(RuntimeError) do
      @factory.open("/path/to/remote") { |f| raise RuntimeError, "b00m" }
    end
  end

  def test_open_without_block_should_return_new_file
    @sftp.expects(:open!).with("/path/to/remote", "r", :permissions => nil).returns("handle")
    @sftp.expects(:close!).never

    f = @factory.open("/path/to/remote")
    assert_instance_of Net::SFTP::Operations::File, f
  end

  def test_open_text_should_raise_not_implemented_for_protocol_versions_before_4
    @sftp.expects(:protocol).returns(stub('protocol', :version => 3))
    @sftp.expects(:open_text!).never

    assert_raises(NotImplementedError) { @factory.open_text("/path/to/remote") }
  end

  def test_open_text_should_raise_not_implemented_when_server_lacks_text_seek_extension
    @sftp.expects(:protocol).returns(stub('protocol', :version => 4))
    @sftp.expects(:extensions).returns("newline" => "\n")
    @sftp.expects(:open_text!).never

    assert_raises(NotImplementedError) { @factory.open_text("/path/to/remote") }
  end

  def test_open_text_with_block_should_yield_reader_and_close_it
    @sftp.expects(:protocol).returns(stub('protocol', :version => 4))
    @sftp.expects(:extensions).returns("text-seek" => "", "newline" => "\r\n")
    @sftp.expects(:open_text!).with("/path/to/remote").returns("handle")
    @sftp.expects(:close!).with("handle")

    called = false
    @factory.open_text("/path/to/remote") do |reader|
      called = true
      assert_instance_of Net::SFTP::Operations::TextReader, reader
      assert_equal "\r\n", reader.newline
    end

    assert called
  end

  def test_open_text_with_block_should_close_reader_even_if_exception_is_raised
    @sftp.expects(:protocol).returns(stub('protocol', :version => 4))
    @sftp.expects(:extensions).returns("text-seek" => "")
    @sftp.expects(:open_text!).with("/path/to/remote").returns("handle")
    @sftp.expects(:close!).with("handle")

    assert_raises(RuntimeError) do
      @factory.open_text("/path/to/remote") { |reader| raise RuntimeError, "b00m" }
    end
  end

  def test_open_text_without_block_should_return_new_reader
    @sftp.expects(:protocol).returns(stub('protocol', :version => 6))
    @sftp.expects(:extensions).returns("text-seek" => "")
    @sftp.expects(:open_text!).with("/path/to/remote").returns("handle")
    @sftp.expects(:close!).never

    reader = @factory.open_text("/path/to/remote")
    assert_instance_of Net::SFTP::Operations::TextReader, reader
    assert_equal "\n", reader.newline
  end

  def test_directory_should_be_true_for_directory
    @sftp.expects(:lstat!).with("/path/to/dir").returns(mock('attrs', :directory? => true))
    assert @factory.directory?("/path/to/dir")
  end

  def test_directory_should_be_false_for_non_directory
    @sftp.expects(:lstat!).with("/path/to/file").returns(mock('attrs', :directory? => false))
    assert !@factory.directory?("/path/to/file")
  end
end
