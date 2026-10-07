require 'net/ssh/loggable'
require 'net/sftp/constants'

module Net; module SFTP; module Protocol

  # The abstract superclass of the specific implementations for each supported
  # SFTP protocol version. It implements general packet parsing logic, and
  # provides a way for subclasses to send requests.
  class Base
    include Net::SSH::Loggable
    include Net::SFTP::Constants
    include Net::SFTP::Constants::PacketTypes

    # The SFTP session object that acts as client to this protocol instance
    attr_reader :session

    # Create a new instance of a protocol driver, servicing the given session.
    def initialize(session)
      @session = session
      self.logger = session.logger
      @request_id_counter = -1
    end

    # Attept to parse the given packet. If the packet is of an unsupported
    # type, an exception will be raised. Returns the parsed data as a hash
    # (the keys in the hash are packet-type specific).
    def parse(packet)
      case packet.type
      when FXP_STATUS         then parse_status_packet(packet)
      when FXP_HANDLE         then parse_handle_packet(packet)
      when FXP_DATA           then parse_data_packet(packet)
      when FXP_NAME           then parse_name_packet(packet)
      when FXP_ATTRS          then parse_attrs_packet(packet)
      when FXP_EXTENDED_REPLY then parse_extended_reply_packet(packet)
      else raise NotImplementedError, "unknown packet type: #{packet.type}"
      end
    end

    # Sends a FXP_EXTENDED "check-file" request to the server, asking it to
    # hash the file identified by +handle+ (as returned by FXP_OPEN).
    # +algorithms+ is an array of hash algorithm names (or a single,
    # comma-delimited string) that the client is willing to accept; the
    # server selects one of them. +start_offset+ and +length+ delimit the
    # region of the file to hash (a +length+ of zero means "to end of
    # file"), and +block_size+ is the size of the blocks the region should
    # be split into before hashing (zero means "hash the region as a
    # single block"). Returns the new packet id.
    #
    # This is only valid when the server advertised the "check-file"
    # extension during version negotiation (see Net::SFTP::Session#extensions).
    def check_file(handle, algorithms, start_offset, length, block_size)
      list = algorithms.is_a?(Array) ? algorithms.join(",") : algorithms.to_s
      send_request(FXP_EXTENDED, :string, "check-file", :string, handle,
        :string, list, :int64, start_offset, :int64, length, :long, block_size)
    end

    # Parses an FXP_EXTENDED_REPLY packet and returns a hash with one key,
    # :extended_reply, which contains the raw (unparsed) extension-specific
    # payload of the reply. Interpreting the payload is left to the caller,
    # since its format depends on the extension that was requested.
    def parse_extended_reply_packet(packet)
      { :extended_reply => packet.read(packet.available) }
    end

    private

      # Send a new packet of the given type, and with the given data arguments.
      # A new request identifier will be allocated to this request, and will
      # be returned.
      def send_request(type, *args)
        @request_id_counter += 1
        session.send_packet(type, :long, @request_id_counter, *args)
        return @request_id_counter
      end
  end

end; end; end
