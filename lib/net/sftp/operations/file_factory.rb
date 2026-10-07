require 'net/ssh/loggable'
require 'net/sftp/operations/file'
require 'net/sftp/operations/text_reader'

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
    #   open_text(name) -> text_reader
    #   open_text(name) { |reader| ... }
    #
    # Attempt to open a file on the remote server in text mode, returning a
    # Net::SFTP::Operations::TextReader that allows the file to be read (and
    # repositioned) by logical line number rather than by byte offset.
    #
    # This requires the server to implement version 4 or newer of the SFTP
    # protocol, and to advertise the "text-seek" extension during version
    # negotiation. If either requirement is not met, NotImplementedError is
    # raised--line positions are never guessed from local byte counts.
    #
    # If a block is given, the new TextReader instance will be yielded to
    # it, and closed automatically when the block terminates. Otherwise the
    # object will be returned, and it is the caller's responsibility to
    # close it.
    #
    #   sftp.file.open_text("/tmp/log.txt") do |reader|
    #     reader.seek_line(1000)
    #     reader.each_line { |line| process(line) }
    #   end
    def open_text(name, &block)
      version = sftp.protocol.version
      if version < 4
        raise NotImplementedError, "text-mode reads require SFTP protocol version 4 or newer, but the server negotiated version #{version}"
      end

      extensions = sftp.extensions || {}
      unless extensions.key?("text-seek")
        raise NotImplementedError, 'the server did not advertise the "text-seek" extension, so line-based positioning is not supported'
      end

      handle = sftp.open_text!(name)
      reader = Operations::TextReader.new(sftp, handle, extensions["newline"])

      if block_given?
        begin
          yield reader
        ensure
          reader.close
        end
      else
        return reader
      end
    end

    # Returns +true+ if the argument refers to a directory on the remote host.
    def directory?(path)
      sftp.lstat!(path).directory?
    end
  end

end; end; end
