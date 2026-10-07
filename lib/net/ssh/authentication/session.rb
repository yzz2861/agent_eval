require 'net/ssh/loggable'
require 'net/ssh/transport/constants'
require 'net/ssh/authentication/constants'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/authentication/methods/none'
require 'net/ssh/authentication/methods/publickey'
require 'net/ssh/authentication/methods/hostbased'
require 'net/ssh/authentication/methods/password'
require 'net/ssh/authentication/methods/keyboard_interactive'

module Net
  module SSH
    module Authentication
      # Raised if the current authentication method is not allowed
      class DisallowedMethod < Net::SSH::Exception
      end

      # Represents an authentication session. It manages the authentication of
      # a user over an established connection (the "transport" object, see
      # Net::SSH::Transport::Session).
      #
      # The use of an authentication session to manage user authentication is
      # internal to Net::SSH (specifically Net::SSH.start). Consumers of the
      # Net::SSH library will never need to access this class directly.
      class Session
        include Loggable
        include Constants
        include Transport::Constants

        # The maximum number of passes over the authentication method list
        # that will be attempted. Each new pass is only started when the
        # previous one made progress (i.e. the server reported a partial
        # success), so this is simply a safeguard against misbehaving
        # servers that report partial success indefinitely without ever
        # completing the authentication.
        MAX_AUTH_PASSES = 16

        # transport layer abstraction
        attr_reader :transport

        # the list of authentication methods to try
        attr_reader :auth_methods

        # the list of authentication methods that are allowed
        attr_reader :allowed_auth_methods

        # a hash of options, given at construction time
        attr_reader :options

        # the list of authentication methods that the server has accepted
        # so far as completed factors of a multi-factor authentication
        # (i.e. methods that received a partial success)
        attr_reader :authenticated_methods

        # Instantiates a new Authentication::Session object over the given
        # transport layer abstraction.
        def initialize(transport, options = {})
          self.logger = transport.logger
          @transport = transport

          @auth_methods = options[:auth_methods] || Net::SSH::Config.default_auth_methods
          @options = options

          @allowed_auth_methods = @auth_methods
          @authenticated_methods = []
          @partial_success = false
          @current_auth_method = nil
          @credential_attempts = {}
        end

        # Attempts to authenticate the given user, in preparation for the next
        # service request. Returns true if an authentication method succeeds in
        # authenticating the user, and false otherwise.
        #
        # Servers may require multiple authentication factors. When a method
        # succeeds only partially, the server replies with USERAUTH_FAILURE
        # whose partial_success flag is set, together with the list of methods
        # that may continue the authentication. In that case the accepted
        # factor is recorded (see #authenticated_methods) and further passes
        # over the remaining methods are made, so that methods appearing
        # earlier in the method list may be revisited in the new stage, and
        # methods that can offer different credentials (e.g. publickey with
        # a different key) may be attempted again.
        def authenticate(next_service, username, password = nil)
          debug { "beginning authentication of `#{username}'" }

          transport.send_message(transport.service_request("ssh-userauth"))
          expect_message(SERVICE_ACCEPT)

          key_manager = KeyManager.new(logger, options)
          keys.each { |key| key_manager.add(key) } unless keys.empty?
          keycerts.each { |keycert| key_manager.add_keycert(keycert) } unless keycerts.empty?
          keycert_data.each { |data| key_manager.add_keycert_data(data) } unless keycert_data.empty?
          key_data.each { |key2| key_manager.add_key_data(key2) } unless key_data.empty?
          default_keys.each { |key| key_manager.add(key) } unless options.key?(:keys) || options.key?(:key_data)

          attempted = []
          passes = 0

          loop do
            passes += 1
            progress = false

            @auth_methods.each do |name|
              next unless @allowed_auth_methods.include?(name)

              attempted << name

              debug { "trying #{name}" }
              begin
                auth_class = Methods.const_get(name.split(/\W+/).map { |p| p.capitalize }.join)
                method = auth_class.new(self,
                                        key_manager: key_manager, password_prompt: options[:password_prompt],
                                        pubkey_algorithms: options[:pubkey_algorithms] || nil)
              rescue NameError
                debug {"Mechanism #{name} was requested, but isn't a known type.  Ignoring it."}
                next
              end

              @partial_success = false
              @current_auth_method = name
              begin
                return true if method.authenticate(next_service, username, password)
              rescue Net::SSH::Authentication::DisallowedMethod
              ensure
                @current_auth_method = nil
              end

              # A partial success means the server accepted this method as
              # one factor of a multi-factor authentication, but requires
              # additional factors before the login is complete, so another
              # pass over the remaining methods is in order.
              progress = true if @partial_success
            end

            break if !progress || passes >= MAX_AUTH_PASSES
          end

          if @authenticated_methods.empty?
            error { "all authorization methods failed (tried #{attempted.uniq.join(', ')})" }
          else
            error do
              "authentication incomplete: server accepted #{@authenticated_methods.join(' + ')} " \
                "but requires additional factors (still allowed: #{@allowed_auth_methods.join(', ')}; " \
                "tried #{attempted.uniq.join(', ')})"
            end
          end
          return false
        ensure
          key_manager.finish if key_manager
        end

        # Records that the given credential (identified by an opaque,
        # non-secret identifier, such as a public key blob) is being used
        # with the given authentication method. Returns true if this is the
        # first attempt with this credential, and false if the same
        # credential has already been tried with this method, in which case
        # it should not be replayed.
        def register_credential_attempt(method_name, credential_id)
          attempts = (@credential_attempts[method_name] ||= [])
          return false if attempts.include?(credential_id)

          attempts << credential_id
          true
        end

        # Blocks until a packet is received. It silently handles USERAUTH_BANNER
        # packets, and will raise an error if any packet is received that is not
        # valid during user authentication.
        def next_message
          loop do
            packet = transport.next_message

            case packet.type
            when USERAUTH_BANNER
              info { packet[:message] }
            # TODO add a hook for people to retrieve the banner when it is sent

            when USERAUTH_FAILURE
              @allowed_auth_methods = packet[:authentications].split(/,/)
              record_completed_factor if packet[:partial_success]
              debug { "allowed methods: #{packet[:authentications]}" }
              return packet

            when USERAUTH_METHOD_RANGE, SERVICE_ACCEPT
              return packet

            when USERAUTH_SUCCESS
              transport.hint :authenticated
              return packet

            else
              raise Net::SSH::Exception, "unexpected message #{packet.type} (#{packet})"
            end
          end
        end

        # Blocks until a packet is received, and returns it if it is of the given
        # type. If it is not, an exception is raised.
        def expect_message(type)
          message = next_message
          raise Net::SSH::Exception, "expected #{type}, got #{message.type} (#{message})" unless message.type == type

          message
        end

        private

        # Notes that the server accepted the method currently being
        # attempted as one completed factor of a multi-factor
        # authentication (a USERAUTH_FAILURE with the partial_success flag
        # set). Subsequent failures within the same method attempt (for
        # other credentials) no longer count as progress on their own.
        def record_completed_factor
          @partial_success = true

          return unless @current_auth_method
          return if @authenticated_methods.include?(@current_auth_method)

          debug { "partial success with #{@current_auth_method}; additional authentication factors required" }
          @authenticated_methods << @current_auth_method
        end

        # Returns an array of paths to the key files usually defined
        # by system default.
        def default_keys
          %w[~/.ssh/id_ed25519 ~/.ssh/id_rsa ~/.ssh/id_dsa ~/.ssh/id_ecdsa
             ~/.ssh2/id_ed25519 ~/.ssh2/id_rsa ~/.ssh2/id_dsa ~/.ssh2/id_ecdsa]
        end

        # Returns an array of paths to the key files that should be used when
        # attempting any key-based authentication mechanism.
        def keys
          Array(options[:keys])
        end

        # Returns an array of paths to the keycert files that should be used when
        # attempting any key-based authentication mechanism.
        def keycerts
          Array(options[:keycerts])
        end

        # Returns an array of the keycert data that should be used when
        # attempting any key-based authentication mechanism.
        def keycert_data
          Array(options[:keycert_data])
        end

        # Returns an array of the key data that should be used when
        # attempting any key-based authentication mechanism.
        def key_data
          Array(options[:key_data])
        end
      end
    end
  end
end
