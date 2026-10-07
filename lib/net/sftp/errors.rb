module Net; module SFTP

  # The base exception class for the SFTP system.
  class Exception < RuntimeError; end

  # A exception class for reporting a non-success result of an operation.
  class StatusException < Net::SFTP::Exception

    # The response object that caused the exception.
    attr_reader :response

    # The error code (numeric)
    attr_reader :code

    # The description of the error
    attr_reader :description

    # Any incident-specific text given when the exception was raised
    attr_reader :text

    # Create a new status exception that reports the given code and
    # description.
    def initialize(response, text=nil)
      @response, @text = response, text
      @code = response.code
      @description = response.message
      @description = Response::MAP[@code] if @description.nil? || @description.empty?
    end

    # Override the default message format, to include the code and
    # description.
    def message
      m = super.dup
      m << " #{text}" if text
      m << " (#{code}, #{description.inspect})"
    end

  end

  # Raised before an upload begins when a remote path already exists with a
  # type that does not match the corresponding local entry.
  class RemoteTypeConflict < Net::SFTP::Exception
    attr_reader :path, :local_type, :remote_type

    def initialize(path, local_type, remote_type)
      @path = path
      @local_type = local_type
      @remote_type = remote_type
      super("remote #{remote_type} at #{path.inspect} conflicts with local #{local_type}")
    end
  end
end; end
