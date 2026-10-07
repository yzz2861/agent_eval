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

    # Returns the protocol version implemented by this driver. (4, in this
    # case)
    def version
      4
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

    # Sends a FXP_OPEN packet to the server, opening the file at +path+
    # read-only and in text mode (SSH_FXF_TEXT), as defined by version 4 of
    # the protocol. The +options+ parameter is a hash used to construct an
    # Attributes object for the request. Returns the new packet id.
    def open_text(path, options={})
      attributes = attribute_factory.new(options)
      send_request(FXP_OPEN, :string, path, :long, FV1::READ | FV1::TEXT, :raw, attributes.to_s)
    end

    # Sends a FXP_EXTENDED "text-seek" request to the server, asking for the
    # byte offset of the start of line +line_number+ (zero-based) in the
    # file identified by +handle+. The handle must have been opened in text
    # mode (see #open_text), and the server must have advertised the
    # "text-seek" extension during version negotiation. Returns the new
    # packet id.
    def text_seek(handle, line_number)
      send_request(FXP_EXTENDED, :string, "text-seek", :string, handle, :int64, line_number)
    end

    # Parses incoming packets. In addition to the packet types understood by
    # earlier protocol versions, version 4 understands FXP_EXTENDED_REPLY
    # packets (used to answer "text-seek" requests).
    def parse(packet)
      if packet.type == FXP_EXTENDED_REPLY
        parse_extended_reply_packet(packet)
      else
        super
      end
    end

    # Parses a FXP_EXTENDED_REPLY packet and returns a hash with a single
    # :offset key, referencing the byte offset returned by the server in
    # response to a "text-seek" request.
    def parse_extended_reply_packet(packet)
      { :offset => packet.read_int64 }
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
