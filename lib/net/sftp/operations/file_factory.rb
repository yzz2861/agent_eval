require 'net/ssh/loggable'
require 'net/sftp/operations/file'
require 'net/sftp/operations/text_file'

module Net; module SFTP; module Operations

  # A factory class for opening files and returning Operations::File instances
  # that wrap the SFTP handles that represent them. This is a convenience
  # class for use when working with files synchronously. Rather than relying
  # on the programmer to provide callbacks that define a state machine that
  # describes the behavior of the program, this class (and Operations::File)
  # provide an interface where calls will block until they return, mimicking
  # the IO class' interface.
  class FileFactory
    # The SFTP session object that drives this file factory.
    attr_reader :sftp

    # Create a new instance on top of the given SFTP session instance.
    def initialize(sftp)
      @sftp = sftp
    end

    # :call-seq:
    #   open(name, flags="r", mode=nil) -> file
    #   open(name, flags="r", mode=nil) { |file| ... }
    #
    # Attempt to open a file on the remote server. The +flags+ parameter
    # accepts the same values as the standard Ruby ::File#open method. The
    # +mode+ parameter must be an integer describing the permissions to use
    # if a new file is being created.
    #
    # If a block is given, the new Operations::File instance will be yielded
    # to it, and closed automatically when the block terminates. Otherwise
    # the object will be returned, and it is the caller's responsibility to
    # close the file.
    #
    #   sftp.file.open("/tmp/names.txt", "w") do |f|
    #     # ...
    #   end
    def open(name, flags="r", mode=nil, &block)
      handle = sftp.open!(name, flags, :permissions => mode)
      file = Operations::File.new(sftp, handle)

      if block_given?
        begin
          yield file
        ensure
          file.close
        end
      else
        return file
      end
    end

    # :call-seq:
    #   open_text(name, flags="r", mode=nil) -> text_file
    #   open_text(name, flags="r", mode=nil) { |text_file| ... }
    #
    # Opens +name+ in text mode (per the rules of the negotiated SFTP
    # protocol version) and returns a Net::SFTP::Operations::TextFile that
    # reads logical lines and positions via the server-side "text-seek"
    # extension. The returned object deliberately has no byte-position API:
    # text mode may translate line endings and encodings, so local byte
    # counts are not valid remote offsets. Use #open instead whenever byte
    # coordinates are required.
    #
    # Raises Net::SFTP::NotSupported if the negotiated SFTP version is less
    # than 4. The server must also advertise the text-seek extension for
    # line positioning; sequential reading works with the server-advertised
    # "newline" sequence (defaulting to "\n").
    def open_text(name, flags="r", mode=nil, &block)
      file = Operations::TextFile.open(sftp, name, flags, mode)

      if block_given?
        begin
          yield file
        ensure
          file.close
        end
      else
        return file
      end
    end

    # Returns +true+ if the argument refers to a directory on the remote host.
    def directory?(path)
      sftp.lstat!(path).directory?
    end
  end

end; end; end
