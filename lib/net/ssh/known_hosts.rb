require 'strscan'
require 'openssl'
require 'delegate'
require 'tempfile'
require 'net/ssh/buffer'
require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH
    module HostKeyEntries
      # regular public key entry
      class PubKey < Delegator
        attr_accessor :source

        def initialize(key, comment: nil, source: nil) # rubocop:disable Lint/MissingSuper
          @key = key
          @comment = comment
          @source = source
        end

        def ssh_type
          @key.ssh_type
        end

        def ssh_types
          [ssh_type]
        end

        def to_blob
          @key.to_blob
        end

        def __getobj__
          Kernel.warn("Calling Net::SSH::Buffer methods on HostKeyEntries PubKey is deprecated")
          @key
        end

        def matches_key?(server_key)
          @key.ssh_type == server_key.ssh_type && @key.to_blob == server_key.to_blob
        end
      end

      # @cert-authority entry
      class CertAuthority
        def ssh_types
          %w[
            ecdsa-sha2-nistp256-cert-v01@openssh.com
            ecdsa-sha2-nistp384-cert-v01@openssh.com
            ecdsa-sha2-nistp521-cert-v01@openssh.com
            ssh-ed25519-cert-v01@openssh.com
            ssh-rsa-cert-v01@openssh.com
            ssh-rsa-cert-v00@openssh.com
          ]
        end

        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        def matches_key?(server_key)
          if ssh_types.include?(server_key.ssh_type)
            server_key.signature_valid? && (server_key.signature_key.to_blob == @key.to_blob)
          else
            false
          end
        end

        # Returns true if the certificate lists no principals (unrestricted) or
        # if the given hostname matches a listed principal. Host-certificate
        # principals are shell-glob patterns, matching OpenSSH, whose
        # sshkey_cert_check_host passes wildcard_pattern=1 so principals like
        # "*.example.com" are matched with match_pattern rather than strcmp.
        def matches_principal?(server_key, hostname)
          server_key.valid_principals.empty? ||
            server_key.valid_principals.any? { |principal| File.fnmatch(principal, hostname) }
        end

        # Returns true if the certificate's validity window covers the current time.
        def matches_validity?(server_key)
          return false if server_key.valid_after && server_key.valid_after > Time.now
          return false if server_key.valid_before && server_key.valid_before < Time.now

          true
        end

        # Returns true if the certificate is a host certificate. A user
        # certificate (type :user) must never authenticate a host.
        def matches_type?(server_key)
          server_key.type == :host
        end

        # Returns true if every critical option in the certificate is one we can
        # enforce. net-ssh enforces none, so any critical option is unsupported
        # and, as OpenSSH does, must cause the certificate to be rejected.
        def critical_options_supported?(server_key)
          server_key.critical_options.empty?
        end
      end
    end

    # Represents the result of a search in known hosts
    # see search_for
    class HostKeys
      include Enumerable
      attr_reader :host

      def initialize(host_keys, host, known_hosts, options = {})
        @host_keys = host_keys
        @host = host
        @known_hosts = known_hosts
        @options = options
      end

      def add_host_key(key)
        @known_hosts.add(@host, key, @options)
        @host_keys.push(key)
      end

      def each(&block)
        @host_keys.each(&block)
      end

      def empty?
        @host_keys.empty?
      end

      # Returns the bare hostname, stripping port and IP portions from the
      # comma-separated host string used internally.
      #
      # Examples:
      #   "server.example.com"            => "server.example.com"
      #   "server.example.com,1.2.3.4"    => "server.example.com"
      #   "[server.example.com]:2222"      => "server.example.com"
      def hostname
        @host.split(",").first.gsub(/\[|\]:\d+/, "")
      end
    end

    # Searches an OpenSSH-style known-host file for a given host, and returns all
    # matching keys. This is used to implement host-key verification, as well as
    # to determine what key a user prefers to use for a given host.
    #
    # This is used internally by Net::SSH, and will never need to be used directly
    # by consumers of the library.
    class KnownHosts
      SUPPORTED_TYPE = %w[ssh-rsa ssh-dss
                          ecdsa-sha2-nistp256
                          ecdsa-sha2-nistp384
                          ecdsa-sha2-nistp521]

      SUPPORTED_TYPE.push('ssh-ed25519') if Net::SSH::Authentication::ED25519Loader::LOADED

      class << self
        # Searches all known host files (see KnownHosts.hostfiles) for all keys
        # of the given host. Returns an enumerable of keys found.
        def search_for(host, options = {})
          HostKeys.new(search_in(hostfiles(options), host, options), host, self, options)
        end

        # Search for all known keys for the given host, in every file given in
        # the +files+ array. Returns the list of keys.
        def search_in(files, host, options = {})
          files.flat_map do |file|
            known_hosts = KnownHosts.new(file)
            known_hosts.keys_for(host, options).each do |entry|
              entry.source = known_hosts.source if entry.respond_to?(:source=)
            end
          end
        end

        # Looks in the given +options+ hash for the :user_known_hosts_file and
        # :global_known_hosts_file keys, and returns an array of all known
        # hosts files. If the :user_known_hosts_file key is not set, the
        # default is returned (~/.ssh/known_hosts and ~/.ssh/known_hosts2). If
        # :global_known_hosts_file is not set, the default is used
        # (/etc/ssh/ssh_known_hosts and /etc/ssh/ssh_known_hosts2).
        #
        # If you only want the user known host files, you can pass :user as
        # the second option.
        def hostfiles(options, which = :all)
          files = []

          files += Array(options[:user_known_hosts_file] || %w[~/.ssh/known_hosts ~/.ssh/known_hosts2]) if which == :all || which == :user

          if which == :all || which == :global
            files += Array(options[:global_known_hosts_file] || %w[/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2])
          end

          return files
        end

        # Looks in all user known host files (see KnownHosts.hostfiles) and tries to
        # add an entry for the given host and key to the first file it is able
        # to.
        def add(host, key, options = {})
          hostfiles(options, :user).each do |file|
            KnownHosts.new(file).add(host, key)
            return
          rescue SystemCallError
            # try the next hostfile
          end
        end

        def update(host, keys, options = {}, remove_old_keys: false, add_keys: keys)
          keys = Array(keys)
          add_keys = Array(add_keys)
          hostfiles(options, :user).each do |file|
            known_hosts = new(file)
            next unless File.file?(known_hosts.source) &&
                        known_hosts.keys_for(host, options).any?

            known_hosts.update(host, keys, options,
                               remove_old_keys: remove_old_keys, add_keys: add_keys)
            return known_hosts.source
          end

          raise Errno::ENOENT, "no writable known_hosts file contains #{host}"
        end

        def source_for_key(host, key, options = {})
          hostfiles(options, :user).find do |file|
            new(file).keys_for(host, options).any? do |entry|
              entry.respond_to?(:matches_key?) && entry.matches_key?(key)
            end
          end
        end
      end

      # The host-key file name that this KnownHosts instance will use to search
      # for keys.
      attr_reader :source

      # Instantiate a new KnownHosts instance that will search the given known-hosts
      # file. The path is expanded file File.expand_path.
      def initialize(source)
        @source = File.expand_path(source)
      rescue ArgumentError
        @source = source
      end

      # Returns an array of all keys that are known to be associatd with the
      # given host. The +host+ parameter is either the domain name or ip address
      # of the host, or both (comma-separated). Additionally, if a non-standard
      # port is being used, it may be specified by putting the host (or ip, or
      # both) in square brackets, and appending the port outside the brackets
      # after a colon. Possible formats for +host+, then, are;
      #
      #   "net.ssh.test"
      #   "1.2.3.4"
      #   "net.ssh.test,1.2.3.4"
      #   "[net.ssh.test]:5555"
      #   "[1,2,3,4]:5555"
      #   "[net.ssh.test]:5555,[1.2.3.4]:5555
      def keys_for(host, options = {})
        keys = []
        return keys unless File.readable?(source)

        entries = host.split(/,/)
        host_name = entries[0]
        host_ip = entries[1]

        File.open(source) do |file|
          file.each_line do |line|
            if line.start_with?('@')
              marker, hosts, type, key_content, comment = line.split(' ')
            else
              marker = nil
              hosts, type, key_content, comment = line.split(' ')
            end

            # Skip empty line or one that is commented
            next if hosts.nil? || hosts.start_with?('#')

            hostlist = hosts.split(',')

            next unless SUPPORTED_TYPE.include?(type)

            found = hostlist.any? { |pattern| match(host_name, pattern) } || known_host_hash?(hostlist, entries)
            next unless found

            found = hostlist.include?(host_ip) if options[:check_host_ip] && entries.size > 1 && hostlist.size > 1
            next unless found

            blob = key_content.unpack("m*").first
            raw_key = Net::SSH::Buffer.new(blob).read_key

            keys <<
              if marker == "@cert-authority"
                HostKeyEntries::CertAuthority.new(raw_key, comment: comment)
              else
                HostKeyEntries::PubKey.new(raw_key, comment: comment)
              end
          end
        end

        keys
      end

      def match(host, pattern)
        if pattern.include?('*') || pattern.include?('?')
          # see man 8 sshd for pattern details
          pattern_regexp = pattern.split('*', -1).map do |x|
            x.split('?', -1).map do |y|
              Regexp.escape(y)
            end.join('.')
          end.join('.*')

          host =~ Regexp.new("\\A#{pattern_regexp}\\z")
        else
          host == pattern
        end
      end

      # Indicates whether one of the entries matches an hostname that has been
      # stored as a HMAC-SHA1 hash in the known hosts.
      def known_host_hash?(hostlist, entries)
        if hostlist.size == 1 && hostlist.first =~ /\A\|1(\|.+){2}\z/
          chunks = hostlist.first.split(/\|/)
          salt = chunks[2].unpack1("m")
          digest = OpenSSL::Digest.new('sha1')
          entries.each do |entry|
            hmac = OpenSSL::HMAC.digest(digest, salt, entry)
            return true if [hmac].pack("m").chomp == chunks[3]
          end
        end
        false
      end

      # Tries to append an entry to the current source file for the given host
      # and key. If it is unable to (because the file is not writable, for
      # instance), an exception will be raised.
      def add(host, key)
        File.open(source, "a") do |file|
          blob = [Net::SSH::Buffer.from(:key, key).to_s].pack("m*").gsub(/\s/, "")
          file.puts "#{host} #{key.ssh_type} #{blob}"
        end
      end

      def update(host, keys, options = {}, remove_old_keys: false, add_keys: keys)
        keys = Array(keys)
        add_keys = Array(add_keys)
        return if keys.empty? && !remove_old_keys

        target_aliases = host.split(",")
        key_blobs = keys.map { |key| Net::SSH::Buffer.from(:key, key).to_s }
        output = []
        missing_key_blobs = add_keys.map { |key| Net::SSH::Buffer.from(:key, key).to_s }

        File.foreach(source) do |line|
          updated_line = update_line(line, target_aliases, key_blobs,
                                     missing_key_blobs, remove_old_keys)
          output << updated_line unless updated_line.nil?
        end

        add_keys.each do |key|
          blob = Net::SSH::Buffer.from(:key, key).to_s
          next unless missing_key_blobs.include?(blob)

          encoded = [blob].pack("m*").gsub(/\s/, "")
          output << "#{host} #{key.ssh_type} #{encoded}\n"
        end

        write_atomically(output.join)
      end

      private

      def update_line(line, target_aliases, key_blobs, missing_key_blobs, remove_old_keys)
        original = line.chomp("\n")
        fields = original.split(/\s+/)
        marker = fields.first && fields.first.start_with?("@") ? fields.shift : nil
        hosts, type, key_content = fields
        return "#{original}\n" unless marker.nil? && type && SUPPORTED_TYPE.include?(type) && key_content

        blob = key_content.unpack("m*").first
        hostlist = hosts.split(",")
        matched_aliases = matching_aliases(hostlist, target_aliases)
        return "#{original}\n" if matched_aliases.empty?

        if key_blobs.include?(blob)
          missing_key_blobs.delete(blob)
          return "#{original}\n"
        end

        return "#{original}\n" unless remove_old_keys

        matched_patterns = hostlist.select do |pattern|
          matched_aliases.any? do |target|
            hostlist.include?(target) || known_host_hash?([pattern], [target])
          end
        end
        remaining_aliases = hostlist - matched_patterns
        return nil if remaining_aliases.empty?

        line_with_aliases(original, fields, remaining_aliases)
      end

      def matching_aliases(hostlist, target_aliases)
        target_aliases.select do |target|
          hostlist.include?(target) ||
            hostlist.any? { |pattern| known_host_hash?([pattern], [target]) }
        end
      end

      def line_with_aliases(original, fields, aliases)
        suffix = fields[1..-1].join(" ")
        "#{aliases.join(',')} #{suffix}\n"
      end

      def write_atomically(content)
        target = File.symlink?(source) ? File.realpath(source) : source
        directory = File.dirname(target)
        Tempfile.create(".known_hosts", directory, binmode: true) do |file|
          file.write(content)
          file.flush
          file.chmod(File.stat(target).mode)
          File.rename(file.path, target)
        end
      end
    end
  end
end
