require 'net/ssh/buffer'
require 'net/ssh/loggable'
require 'socket'

module Net
  module SSH
    module Authentication
      # Forwards one SSH agent connection through a session-specific policy.
      # Every request is parsed according to its declared agent packet length;
      # data arriving in multiple writes is buffered until a complete message is
      # available.
      class AgentForwarder
        include Loggable

        class AgentForwardError < StandardError; end

        SSH2_AGENT_REQUEST_IDENTITIES = 11
        SSH2_AGENT_IDENTITIES_ANSWER = 12
        SSH2_AGENT_SIGN_REQUEST = 13
        SSH2_AGENT_EXTENSION = 27
        SSH_AGENT_FAILURE = 5
        SSH2_AGENT_FAILURE = 30

        SESSION_BIND_EXTENSION = "session-bind@openssh.com".freeze
        MAX_PACKET_LENGTH = 256 * 1024

      attr_reader :upstream, :policy, :session_bind

        def initialize(upstream, policy, logger: nil, session_bind: nil)
          @upstream = upstream
          @policy = policy
          @session_bind = session_bind
          @input = String.new.force_encoding(Encoding::BINARY)
          @output = String.new.force_encoding(Encoding::BINARY)
          @closed = false
          @fatal = false
          self.logger = logger
          bind_session! if @session_bind
        end

        # Called by the SSH channel when bytes arrive from the remote end.
        def send(data, _flags = 0)
          @input << data.to_s.b
          process_packets while !@fatal && packet_ready?
          self
        end
      alias write send

      # Used when the upstream socket is a real IO. The SSH event loop watches
      # the upstream fd and feeds readable bytes here.
      def fill(data)
        @input << data.to_s.b
        process_packets while !@fatal && packet_ready?
        data.to_s.bytesize
      end

        # Called by the SSH event loop to consume bytes destined for the remote
        # end. Complete agent packets are processed synchronously, preserving
        # the protocol's request/response ordering.
        def read(length = 8192)
          return nil if @output.empty?

          @output.slice!(0, @output.bytesize)
        end

        def available
          @output.bytesize
        end

        def shutdown(how = Socket::SHUT_RDWR)
          return if closed?

          upstream.shutdown(how) if upstream.respond_to?(:shutdown)
        rescue IOError, Errno::ENOTCONN
          nil
        end

        def close
          return if closed?

          @closed = true
          upstream.close if upstream.respond_to?(:close) && !upstream.closed?
        end

        def closed?
          @closed || (upstream.respond_to?(:closed?) && upstream.closed?)
        end

        private

        def packet_ready?
          return false if @fatal
          return false if @input.bytesize < 4

          length = @input.unpack1('N')
          !length.between?(1, MAX_PACKET_LENGTH) || @input.bytesize >= 4 + length
        end

        def process_packets
          length = @input.unpack1('N')
          unless length.between?(1, MAX_PACKET_LENGTH)
            @input.slice!(0, 4)
            @input.clear
            @fatal = true
            upstream.close if upstream.respond_to?(:close) && !upstream.closed?
            deny("invalid SSH agent packet length")
            return
          end
          packet = @input.byteslice(4...(4 + length))
          @input.slice!(0, 4 + length)
          dispatch(packet)
        rescue => e
          debug { "agent forwarding packet error: #{e.class}: #{e.message}" }
          @output << failure_packet
        end

        def dispatch(packet)
          type = packet.getbyte(0)
          body = Buffer.new(packet.byteslice(1...packet.bytesize) || String.new)

          case type
          when SSH2_AGENT_REQUEST_IDENTITIES
            forward_identities(packet, body)
          when SSH2_AGENT_SIGN_REQUEST
            forward_signature(packet, body)
          when SSH2_AGENT_EXTENSION
            forward_extension(packet, body)
          else
            deny("unsupported SSH agent request #{type.inspect}")
          end
        end

        def forward_identities(packet, body)
          unless body.eof?
            deny("malformed identities request")
            return
          end

          response = exchange(packet)
          type = response.getbyte(0)
          response_body = Buffer.new(response.byteslice(1...response.bytesize) || String.new)
          if type != SSH2_AGENT_IDENTITIES_ANSWER
            @output << frame(response)
            return
          end

          filtered = filter_identities(response_body)
          @output << if filtered
                       filtered
                     else
                       error { "malformed identities response from upstream agent" }
                       failure_packet
                     end
        end

        def filter_identities(body)
          count = read_long!(body)
          return unless count

          visible_identities = []
          answer = Buffer.new

          count.times do
            blob = read_string!(body)
            comment = read_string!(body)
            return if blob.nil? || comment.nil?

            identity = ::Net::SSH::Authentication::AgentForwardPolicy::IdentityRequest.new(blob: blob, comment: comment)
            decision = policy.allow_identity?(identity)
            next unless decision.allowed

            visible_identities << [blob, comment]
          end
          return unless body.eof?

          answer.write_long(visible_identities.length)
          visible_identities.each do |blob, comment|
            answer.write_string(blob)
            answer.write_string(comment)
          end
          packet(SSH2_AGENT_IDENTITIES_ANSWER, answer.to_s)
        end

        def forward_signature(packet, body)
          blob = read_string!(body)
          data = read_string!(body)
          flags = read_long!(body)
          if blob.nil? || data.nil? || flags.nil? || !body.eof?
            deny("malformed signature request")
            return
          end

          request = ::Net::SSH::Authentication::AgentForwardPolicy::SignatureRequest.new(blob: blob, data: data, flags: flags)
          decision = policy.allow_signature?(request)
          if decision.allowed
            @output << frame(exchange(packet))
          else
            deny(decision.reason)
          end
        end

        def forward_extension(packet, body)
          name = read_string!(body)
          extension_contents = body.content.byteslice(body.position..)
          extension_body = body.remainder_as_buffer
          if name.nil?
            deny("malformed extension request")
            return
          end

          session_bind = parse_session_bind(name, extension_body)
          if name == SESSION_BIND_EXTENSION && session_bind.nil?
            deny("malformed session bind extension")
            return false
          end

          request = ::Net::SSH::Authentication::AgentForwardPolicy::ExtensionRequest.new(
            name: name, contents: extension_contents, session_bind: session_bind
          )
          decision = policy.allow_extension?(request)
          if decision.allowed
            @output << frame(exchange(packet))
          else
            deny(decision.reason)
          end
        end

        def parse_session_bind(name, contents)
          return unless name == SESSION_BIND_EXTENSION

          session_id = read_string!(contents)
          forwarding_value = read_long!(contents)
          upstream_host_key = read_string!(contents)
          downstream_host_key = read_string!(contents)
          return if session_id.nil? || forwarding_value.nil? || upstream_host_key.nil? ||
                    downstream_host_key.nil? || ![0, 1].include?(forwarding_value) || !contents.eof?

          ::Net::SSH::Authentication::AgentForwardPolicy::SessionBindRequest.new(
            session_id: session_id,
            is_forwarding: forwarding_value == 1,
            upstream_host_key: upstream_host_key,
            downstream_host_key: downstream_host_key
          )
        end

        def exchange(packet)
          write_upstream(packet)
          read_upstream_packet
        end

        def bind_session!
          bind = @session_bind
          body = Buffer.from(:string, bind.fetch(:session_id),
                             :long, bind.fetch(:is_forwarding, false) ? 1 : 0,
                             :string, bind.fetch(:upstream_host_key, String.new),
                             :string, bind.fetch(:downstream_host_key))
          request = ::Net::SSH::Authentication::AgentForwardPolicy::SessionBindRequest.new(
            session_id: bind.fetch(:session_id),
            is_forwarding: bind.fetch(:is_forwarding, false),
            upstream_host_key: bind.fetch(:upstream_host_key, String.new),
            downstream_host_key: bind.fetch(:downstream_host_key, String.new)
          )
          decision = policy.allow_extension?(
            ::Net::SSH::Authentication::AgentForwardPolicy::ExtensionRequest.new(name: SESSION_BIND_EXTENSION,
                                                    contents: body.to_s,
                                                    session_bind: request)
          )
          return unless decision.allowed

          extension_body = Buffer.from(:string, SESSION_BIND_EXTENSION, :raw, body.to_s).to_s
          packet_body = [SSH2_AGENT_EXTENSION].pack("C") + extension_body
          response = exchange(packet_body)
          response_type = response.getbyte(0)
          if [SSH_AGENT_FAILURE, SSH2_AGENT_FAILURE].include?(response_type)
            debug { "SSH agent rejected session binding" }
          else
            debug { "established SSH agent session binding" }
          end
        rescue => e
          debug { "SSH agent session binding unavailable: #{e.class}: #{e.message}" }
        end

        def write_upstream(packet)
          data = [packet.bytesize].pack('N') + packet
          if upstream.respond_to?(:write)
            upstream.write(data)
          else
            upstream.send(data, 0)
          end
        end

        def read_upstream_packet
          header = read_upstream_exact(4)
          raise AgentForwardError, "agent connection closed" if header.bytesize != 4

          length = header.unpack1('N')
          raise AgentForwardError, "invalid agent packet length" unless length.between?(1, MAX_PACKET_LENGTH)

          body = read_upstream_exact(length)
          raise AgentForwardError, "truncated agent packet" if body.bytesize != length

          body
        end

        def read_upstream_exact(length)
          buffer = String.new.force_encoding(Encoding::BINARY)
          while buffer.bytesize < length
            chunk = upstream.read(length - buffer.bytesize)
            raise AgentForwardError, "agent connection closed" if chunk.nil?
            buffer << chunk.b
          end
          buffer
        end

        def read_long!(buffer)
          return if buffer.available < 4

          position = buffer.position
          value = buffer.content.unpack1("@#{position}N")
          buffer.position = position + 4
          value
        end

        def read_string!(buffer)
          return if buffer.available < 4

          length = read_long!(buffer)
          return if length.nil? || buffer.available < length

          position = buffer.position
          value = buffer.content.byteslice(position...(position + length))
          buffer.position = position + length
          value
        end

        def deny(reason)
          debug { "denied forwarded SSH agent request: #{reason}" }
          @output << failure_packet
        end

        def failure_packet
          packet(SSH2_AGENT_FAILURE)
        end

        def packet(type, body = String.new)
          [body.bytesize + 1].pack('N') + [type].pack('C') + body.b
        end

        def frame(packet)
          [packet.bytesize].pack('N') + packet
        end

      end
    end
  end
end
