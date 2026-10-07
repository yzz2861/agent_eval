require 'net/sftp/protocol/03/base'
require 'net/sftp/protocol/04/attributes'
require 'net/sftp/protocol/04/name'

module Net; module SFTP; module Protocol; module V04

  # Wraps the low-level SFTP calls for version 4 of the SFTP protocol. Also
  # implements the updated FXP_NAME packet parsing as mandated by v4 of the
  # protocol.
  #
  # None of these protocol methods block--all of them return immediately,
  # requiring the SSH event loop to be run while the server response is
  # pending.
  #
  # You will almost certainly never need to use this driver directly. Please
  # see Net::SFTP::Session for the recommended interface.
  class Base < V03::Base
    include Net::SFTP::Constants::Extensions

    # Returns the protocol version implemented by this driver. (4, in this
    # case)
    def version
      4
    end

    # Sends a FXP_OPEN packet to the server. In addition to the flags and
    # options understood by protocol versions 1-3, the +options+ hash may
    # contain a truthy +:text+ entry, which causes the file to be opened in
    # text mode (SSH_FXF_TEXT). This is only supported in version 4 and
    # later of the protocol.
    def open(path, flags, options)
      options = options.dup
      text_mode = options.delete(:text)

      flags = normalize_open_flags(flags)

      if flags & (IO::WRONLY | IO::RDWR) != 0
        sftp_flags = FV1::WRITE
        sftp_flags |= FV1::READ if flags & IO::RDWR != 0
        sftp_flags |= FV1::APPEND if flags & IO::APPEND != 0
      else
        sftp_flags = FV1::READ
      end

      sftp_flags |= FV1::CREAT if flags & IO::CREAT != 0
      sftp_flags |= FV1::TRUNC if flags & IO::TRUNC != 0
      sftp_flags |= FV1::EXCL  if flags & IO::EXCL  != 0
      sftp_flags |= FV4::TEXT  if text_mode

      attributes = attribute_factory.new(options)

      send_request(FXP_OPEN, :string, path, :long, sftp_flags, :raw, attributes.to_s)
    end

    # Sends a text-seek FXP_EXTENDED packet for the given text-mode
    # +handle+, asking the server to position the handle at the start of
    # logical line +line+ (0-based). The server answers with a regular
    # FXP_STATUS packet.
    def text_seek(handle, line)
      send_request(FXP_EXTENDED, :string, TEXT_SEEK, :string, handle, :int64, line)
    end

    # As of v4 of the SFTP protocol, the "longname" member was removed from the
    # FXP_NAME structure. This method is essentially the same as the previous
    # implementation, but omits longname.
    def parse_name_packet(packet)
      names = []

      packet.read_long.times do
        filename = packet.read_string
        attrs    = attribute_factory.from_buffer(packet)
        names   << name_factory.new(filename, attrs)
      end

      { :names => names }
    end

    # Sends a FXP_STAT packet to the server for the given +path+, and with the
    # given +flags+. If +flags+ is nil, it defaults to F_SIZE | F_PERMISSIONS |
    # F_ACCESSTIME | F_CREATETIME | F_MODIFYTIME | F_ACL | F_OWNERGROUP |
    # F_SUBSECOND_TIMES | F_EXTENDED (see Net::SFTP::Protocol::V04::Attributes
    # for those constants).
    def stat(path, flags=nil)
      send_request(FXP_STAT, :string, path, :long, flags || DEFAULT_FLAGS)
    end

    # Sends a FXP_LSTAT packet to the server for the given +path+, and with the
    # given +flags+. If +flags+ is nil, it defaults to F_SIZE | F_PERMISSIONS |
    # F_ACCESSTIME | F_CREATETIME | F_MODIFYTIME | F_ACL | F_OWNERGROUP |
    # F_SUBSECOND_TIMES | F_EXTENDED (see Net::SFTP::Protocol::V04::Attributes
    # for those constants).
    def lstat(path, flags=nil)
      send_request(FXP_LSTAT, :string, path, :long, flags || DEFAULT_FLAGS)
    end

    # Sends a FXP_FSTAT packet to the server for the given +path+, and with the
    # given +flags+. If +flags+ is nil, it defaults to F_SIZE | F_PERMISSIONS |
    # F_ACCESSTIME | F_CREATETIME | F_MODIFYTIME | F_ACL | F_OWNERGROUP |
    # F_SUBSECOND_TIMES | F_EXTENDED (see Net::SFTP::Protocol::V04::Attributes
    # for those constants).
    def fstat(handle, flags=nil)
      send_request(FXP_FSTAT, :string, handle, :long, flags || DEFAULT_FLAGS)
    end

    protected

      # The default flags used if the +flags+ parameter is nil for any of the
      # #stat, #lstat, or #fstat operations.
      DEFAULT_FLAGS = Attributes::F_SIZE |
                      Attributes::F_PERMISSIONS |
                      Attributes::F_ACCESSTIME |
                      Attributes::F_CREATETIME |
                      Attributes::F_MODIFYTIME |
                      Attributes::F_ACL |
                      Attributes::F_OWNERGROUP |
                      Attributes::F_SUBSECOND_TIMES |
                      Attributes::F_EXTENDED

      # Returns the Attributes class used by this version of the protocol
      # (Net::SFTP::Protocol::V04::Attributes, in this case)
      def attribute_factory
        V04::Attributes
      end

      # Returns the Name class used by this version of the protocol
      # (Net::SFTP::Protocol::V04::Name, in this case)
      def name_factory
        V04::Name
      end
  end

end; end; end; end
