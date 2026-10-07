require 'net/ssh/buffer'
require 'net/ssh/loggable'

module Net
  module SSH
    module Service
      class Forward
        # Frame-aware proxy for one forwarded authentication-agent channel.
        class AgentProxy
          include Loggable

          SSH2_AGENTC_REQUEST_IDENTITIES = 11
          SSH2_AGENT_IDENTITIES_ANSWER   = 12
          SSH2_AGENTC_SIGN_REQUEST        = 13
          SSH2_AGENTC_EXTENSION           = 27
          SSH2_AGENT_SUCCESS              = 6
          SSH2_AGENT_FAILURE              = 30

          QUERY_EXTENSION = "query".freeze
          SESSION_BIND_EXTENSION = "session-bind@openssh.com".freeze

          Frame = Struct.new(:type, :payload, keyword_init: true)

          attr_reader :channel

          def initialize(channel, agent_socket, policy, session_binding: nil, logger: nil)
            @channel = channel
            @agent_socket = agent_socket
            @policy = policy
            @session_binding = session_binding
            self.logger = logger

            @remote_buffer = +"".b
            @agent_buffer = +"".b
            @pending = []
            @closed = false
            @ready = session_binding.nil?
          end

          def start
            send_extension_query if @session_binding
            register_channel_handlers
          end

          def receive_remote_data(data)
            @remote_buffer << data.b
            process_remote_frames
          end

          def receive_agent_data(data)
            @agent_buffer << data.b
            process_agent_frames
          rescue StandardError => e
            error { "local agent proxy failed: #{e.message}" }
            send_failure
            close
          end

          def agent_readable?
            data = if @agent_socket.respond_to?(:read_available)
                     @agent_socket.read_available
                   else
                     @agent_socket.read(65_536)
                   end
            receive_agent_data(data) if data && !data.empty?
          end

          def close
            return if @closed

            @closed = true
            @agent_socket.close rescue nil
            @channel.close unless @channel_closing
          end

          def mark_channel_closing
            @channel_closing = true
          end

          private

          def register_channel_handlers
            @channel.on_data { |_channel, data| receive_remote_data(data) }
            @channel.on_extended_data { |_channel, _type, data| receive_remote_data(data) }
            @channel.on_close do
              mark_channel_closing
              close
            end
          end

          def send_extension_query
            send_to_agent(SSH2_AGENTC_EXTENSION,
                          Net::SSH::Buffer.from(:string, QUERY_EXTENSION))
            @pending << :extension_query
          end

          def send_session_binding
            binding = @session_binding
            payload = Net::SSH::Buffer.from(
              :string, SESSION_BIND_EXTENSION,
              :string, binding.fetch(:host_key_algorithm),
              :string, binding.fetch(:session_id),
              :string, binding.fetch(:host_key_blob),
              :bool, true
            )
            send_to_agent(SSH2_AGENTC_EXTENSION, payload)
            @pending << :session_binding
          end

          def process_remote_frames
            while (frame = read_frame(@remote_buffer))
              request = parse_request(frame)
              if !@ready || !allowed?(frame, request)
                @pending << :failure
              else
                send_frame_to_agent(frame)
                @pending << frame
              end
              flush_pending_failures
            end
          rescue StandardError => e
            debug { "rejecting malformed agent request: #{e.message}" }
            @pending << :failure
            flush_pending_failures
          end

          def process_agent_frames
            while (frame = read_frame(@agent_buffer))
              handle_agent_frame(frame)
            end
          end

          def handle_agent_frame(frame)
            pending = @pending.shift
            raise "agent response without request" unless pending

            case pending
            when :extension_query
              handle_extension_query_response(frame)
            when :session_binding
              handle_session_binding_response(frame)
            when Frame
              send_to_channel(pending.type == SSH2_AGENTC_REQUEST_IDENTITIES ? filter_identities(frame) : frame)
            else
              raise "invalid pending agent request #{pending.inspect}"
            end
          end

          def handle_extension_query_response(frame)
            if frame.type == SSH2_AGENT_SUCCESS && supported_extensions(frame.payload).include?(SESSION_BIND_EXTENSION)
              send_session_binding
            else
              raise "session binding unavailable"
            end
          end

          def handle_session_binding_response(frame)
            raise "session binding rejected" unless frame.type == SSH2_AGENT_SUCCESS

            @ready = true
          end

          def supported_extensions(payload)
            payload.split("\0").reject(&:empty?)
          end

          def allowed?(frame, request)
            if frame.type == SSH2_AGENTC_REQUEST_IDENTITIES
              @policy.allow_identities_request?(request)
            elsif frame.type == SSH2_AGENTC_SIGN_REQUEST
              @policy.allow_sign?(request)
            else
              false
            end
          end

          def parse_request(frame)
            buffer = Net::SSH::Buffer.new(frame.payload)

            case frame.type
            when SSH2_AGENTC_REQUEST_IDENTITIES
              ensure_eof!(buffer, "identity request")
              {}
            when SSH2_AGENTC_SIGN_REQUEST
              blob = read_string(buffer)
              data = read_string(buffer)
              flags = buffer.read_long
              raise "missing signature flags" if flags.nil?
              ensure_eof!(buffer, "signature request")
              key = begin
                Net::SSH::Buffer.new(blob).read_key
              rescue StandardError
                nil
              end
              { key: key, blob: blob, data: data, flags: flags }
            else
              {}
            end
          end

          def filter_identities(frame)
            raise "agent identity request failed" if frame.type == SSH2_AGENT_FAILURE
            raise "bad identity response type #{frame.type}" unless frame.type == SSH2_AGENT_IDENTITIES_ANSWER

            buffer = Net::SSH::Buffer.new(frame.payload)
            count = buffer.read_long
            raise "missing identity count" if count.nil?

            identities = count.times.map do
              blob = read_string(buffer)
              comment = read_string(buffer)
              { blob: blob, comment: comment }
            end
            ensure_eof!(buffer, "identity response")

            visible = @policy.filter_identities(identities)
            answer = Net::SSH::Buffer.new
            answer.write_long(visible.length)
            visible.each do |identity|
              answer.write_string(identity[:blob])
              answer.write_string(identity[:comment])
            end
            Frame.new(type: SSH2_AGENT_IDENTITIES_ANSWER, payload: answer)
          end

          def read_frame(source)
            return nil if source.bytesize < 4

            length = source.byteslice(0, 4).unpack1("N")
            raise "invalid agent frame length" if length < 1
            return nil if source.bytesize < 4 + length

            total = 4 + length
            packet = source.byteslice(0, total)
            source.replace(source.byteslice(total..-1) || +"")
            type = packet.getbyte(4)
            Frame.new(type: type, payload: packet.byteslice(5, length - 1))
          end

          def read_string(buffer)
            value = buffer.read_string
            raise "truncated string" if value.nil?
            value
          end

          def ensure_eof!(buffer, name)
            raise "trailing #{name} data" unless buffer.eof?
          end

          def flush_pending_failures
            while @pending.first == :failure
              @pending.shift
              send_failure
            end
          end

          def send_failure
            send_to_channel(Frame.new(type: SSH2_AGENT_FAILURE, payload: +""))
          end

          def send_frame_to_agent(frame)
            send_to_agent(frame.type, frame.payload)
          end

          def send_to_agent(type, payload = +"")
            payload = payload.to_s.b
            packet = [payload.bytesize + 1, type].pack("NC") + payload
            @agent_socket.send(packet, 0)
          end

          def send_to_channel(frame)
            payload = frame.payload.to_s.dup.force_encoding(Encoding::BINARY)
            packet = [payload.bytesize + 1, frame.type].pack("NC") + payload.b
            @channel.send_data(packet)
          end
        end
      end
    end
  end
end
