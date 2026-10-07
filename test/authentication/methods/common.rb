module Authentication
  module Methods
    module Common
      include Net::SSH::Authentication::Constants

      private

      def socket(options = {})
        @socket ||= stub("socket", client_name: "me.ssh.test")
      end

      def transport(options = {})
        @transport ||= MockTransport.new(options.merge(socket: socket))
      end

      def session(options = {})
        @session ||= begin
          sess = stub("auth-session", logger: nil, transport: transport(options))
          def sess.next_message
            transport.next_message
          end
          attempted_credentials = Hash.new { |hash, key| hash[key] = [] }
          sess.define_singleton_method(:register_credential_attempt) do |method_name, credential_id|
            attempts = attempted_credentials[method_name]
            if attempts.include?(credential_id)
              false
            else
              attempts << credential_id
              true
            end
          end
          sess
        end
      end

      def reset_session(options = {})
        @transport = nil
        @session = nil
        session(options)
      end
    end
  end
end
