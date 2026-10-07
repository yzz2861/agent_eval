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
        def initialize(key, comment: nil) # rubocop:disable Lint/MissingSuper
          @key = key
          @comment = comment
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
          files.flat_map { |file| KnownHosts.new(file).keys_for(host, options) }
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

        # Atomically replaces, in the first user known-host file that contains
        # an entry for +host+, the host keys listed in +remove_keys+ with the
        # given +add_keys+. Only lines belonging to +host+ (hostname, aliases
        # and port are all considered) are touched; entries for unrelated
        # hosts, including hashed entries, are left byte-for-byte intact.
        #
        # Files that do not already contain a matching entry are skipped, so
        # new keys are learned alongside an existing record rather than being
        # scattered over every configured host file. Returns true when a file
        # was updated.
        def replace(host, add_keys, remove_keys, options = {})
          hostfiles(options, :user).each do |file|
            next unless File.readable?(file)

            known_hosts = KnownHosts.new(file)
            next unless known_hosts.keys_for(host, options).any?

            known_hosts.replace_keys(host, Array(add_keys), Array(remove_keys))
            return true
          end

          false
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

      # Removes +remove_keys+ for the given +host+ from this file and appends
      # +add_keys+, rewriting the file atomically. The original file is left
      # untouched if no line needs to change or if the rewrite cannot be
      # completed. See KnownHosts.replace for the host-matching semantics.
      def replace_keys(host, add_keys, remove_keys = [])
        add_keys = Array(add_keys)
        remove_blobs = Array(remove_keys).map(&:to_blob)
        entries = host.split(",")

        kept_lines = []
        removed = false

        File.open(source) do |file|
          file.each_line do |line|
            parsed = parse_line(line)

            if parsed && line_belongs_to_host?(parsed, entries) && remove_blobs.include?(parsed[:blob])
              removed = true
              next
            end

            kept_lines << line
          end
        end

        present_blobs = kept_lines.filter_map { |line| (parse_line(line) || {})[:blob] }
        keys_to_add = add_keys.reject { |key| present_blobs.include?(key.to_blob) }

        return false unless removed || keys_to_add.any?

        atomic_write(kept_lines, keys_to_add, host)
        true
      end

      private

      # Parses a single known-hosts line into its marker, host patterns, key
      # type, raw public-key blob and key object. Returns nil for blank lines,
      # comments, unsupported key types or malformed entries.
      def parse_line(line)
        fields = line.chomp.split(/\s+/)
        return nil if fields.empty? || fields.first.start_with?('#')

        if fields.first.start_with?('@')
          marker = fields.shift
          return nil unless %w[@cert-authority @revoked].include?(marker)
        end

        hosts, type, key_content = fields
        return nil unless hosts && type && key_content && SUPPORTED_TYPE.include?(type)

        blob = key_content.unpack1("m*")
        key = Net::SSH::Buffer.new(blob).read_key

        { marker: marker, hosts: hosts, type: type, blob: blob, key: key }
      rescue StandardError
        nil
      end

      # True when every host pattern in the parsed line refers to the logical
      # host identified by +entries+ (the comma-separated hostname/IP and port
      # string used for lookup). Requiring all patterns to match ensures a
      # line shared with an unrelated alias or host is never deleted.
      def line_belongs_to_host?(parsed, entries)
        patterns = parsed[:hosts].split(',')
        return false if patterns.empty?

        patterns.all? { |pattern| pattern_matches_host?(pattern, entries) }
      end

      def pattern_matches_host?(pattern, entries)
        if hashed_pattern?(pattern)
          hashed_pattern_matches?(pattern, entries)
        else
          entries.any? { |entry| plain_pattern_matches_entry?(entry, pattern) }
        end
      end

      # Port-aware counterpart of #match for plain-text host patterns. A
      # pattern for the default port never matches a non-standard-port entry
      # (and vice versa), so records such as "host" and "[host]:2222" stay
      # independent.
      def plain_pattern_matches_entry?(entry, pattern)
        entry_host, entry_port = split_host_port(entry)
        pattern_host, pattern_port = split_host_port(pattern)

        # A plain pattern never matches a port-scoped entry and vice versa.
        return false unless entry_port.nil? == pattern_port.nil?
        return false if entry_port && entry_port != pattern_port

        if pattern_host.include?('*') || pattern_host.include?('?')
          match(entry_host, pattern_host)
        else
          entry_host == pattern_host
        end
      end

      def split_host_port(value)
        if value.start_with?('[') && value =~ /\A\[(.+)\]:(\d+)\z/
          [Regexp.last_match(1), Regexp.last_match(2)]
        elsif value.start_with?('[') && value =~ /\A\[(.+)\]\z/
          [Regexp.last_match(1), nil]
        else
          [value, nil]
        end
      end

      def hashed_pattern?(pattern)
        pattern =~ /\A\|1(\|.+){2}\z/
      end

      def hashed_pattern_matches?(pattern, entries)
        chunks = pattern.split(/\|/)
        salt = chunks[2].unpack1("m")
        expected = chunks[3]
        digest = OpenSSL::Digest.new('sha1')

        entries.any? do |entry|
          hmac = OpenSSL::HMAC.digest(digest, salt, entry)
          [hmac].pack("m").chomp == expected
        end
      end

      # Rewrites the source file via a temporary file in the same directory
      # and renames it into place, so a failure never leaves a truncated
      # known-hosts file. Preserves the original file's permissions.
      def atomic_write(kept_lines, keys_to_add, host)
        File.open(source) do |existing|
          mode = existing.lstat.mode & 0o777

          Tempfile.create(File.basename(source), File.dirname(source)) do |temp|
            temp.chmod(mode)
            kept_lines.each { |line| temp.write(line) }

            keys_to_add.each do |key|
              blob = [Net::SSH::Buffer.from(:key, key).to_s].pack("m*").gsub(/\s/, "")
              temp.puts "#{host} #{key.ssh_type} #{blob}"
            end

            temp.flush
            File.rename(temp.path, source)
          end
        end
      end
    end
  end
end
