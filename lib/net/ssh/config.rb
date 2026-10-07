module Net
  module SSH
    # The Net::SSH::Config class is used to parse OpenSSH configuration files,
    # and translates that syntax into the configuration syntax that Net::SSH
    # understands. This lets Net::SSH scripts read their configuration (to
    # some extent) from OpenSSH configuration files (~/.ssh/config, /etc/ssh_config,
    # and so forth).
    #
    # Only a subset of OpenSSH configuration options are understood:
    #
    # * ChallengeResponseAuthentication => maps to the :auth_methods option challenge-response (then coleasced into keyboard-interactive)
    # * KbdInteractiveAuthentication => maps to the :auth_methods keyboard-interactive
    # * CertificateFile => maps to the :keycerts option
    # * Ciphers => maps to the :encryption option
    # * Compression => :compression
    # * CompressionLevel => :compression_level
    # * ConnectTimeout => maps to the :timeout option
    # * ForwardAgent => :forward_agent
    # * GlobalKnownHostsFile => :global_known_hosts_file
    # * HostBasedAuthentication => maps to the :auth_methods option
    # * HostKeyAlgorithms => maps to :host_key option
    # * HostKeyAlias => :host_key_alias
    # * HostName => :host_name
    # * IdentityFile => maps to the :keys option
    # * IdentityAgent => :identity_agent
    # * IdentitiesOnly => :keys_only
    # * CheckHostIP => :check_host_ip
    # * Macs => maps to the :hmac option
    # * PasswordAuthentication => maps to the :auth_methods option password
    # * Port => :port
    # * PreferredAuthentications => maps to the :auth_methods option
    # * ProxyCommand => maps to the :proxy option
    # * ProxyJump => maps to the :proxy option
    # * PubKeyAuthentication => maps to the :auth_methods option
    # * RekeyLimit => :rekey_limit
    # * StrictHostKeyChecking => :verify_host_key
    # * User => :user
    # * UserKnownHostsFile => :user_known_hosts_file
    # * NumberOfPasswordPrompts => :number_of_password_prompts
    # * FingerprintHash => :fingerprint_hash
    #
    # * CanonicalizeHostname => :canonicalize_hostname
    # * CanonicalDomains => :canonical_domains
    # * CanonicalizeFallbackLocal => :canonicalize_fallback_local
    # * CanonicalizeMaxDots => :canonicalize_max_dots
    # * CanonicalizePermittedCNAMEs => :canonicalize_permitted_cnames
    #
    # When CanonicalizeHostname is enabled, the configuration is loaded in two
    # passes: the first pass resolves the settings for the original host name,
    # the host name is then canonicalized by appending each of the declared
    # CanonicalDomains in turn (via the injectable resolver), and the
    # configuration is re-read for the canonical name. Values obtained in the
    # first pass keep precedence over values found in the second pass, so
    # HostName, Include, ProxyJump/ProxyCommand and friends behave exactly as
    # they would without canonicalization. Match conditions are re-evaluated
    # during the second pass: the +canonical+ and +final+ Match criteria are
    # honored, and +originalhost+ matches the name given before
    # canonicalization.
    #
    # Note that you will never need to use this class directly--you can control
    # whether the OpenSSH configuration files are read by passing the :config
    # option to Net::SSH.start. (They are, by default.)
    class Config
      # Raised when CanonicalizeHostname is in effect, the host name could not
      # be canonicalized (or the resulting CNAME is not permitted), and
      # CanonicalizeFallbackLocal is disabled.
      class CanonicalizationError < StandardError; end

      # The outcome of resolving a host name against the SSH configuration,
      # including the audit trail needed to verify which pass each final
      # option value originated from.
      #
      # * +original_host+  - the host name exactly as given by the caller.
      # * +matched_host+   - the host name used for Host/Match lookups in the
      #   effective pass (the canonical name when canonicalization succeeded,
      #   otherwise the original name).
      # * +host_name+      - the host name to actually connect to (an explicit
      #   HostName directive wins; otherwise the matched host).
      # * +fallback+       - +:local+ when canonicalization failed and the
      #   original name was kept per CanonicalizeFallbackLocal, else nil.
      # * +options+        - the translated Net::SSH options (same hash that
      #   Config.for returns).
      # * +option_sources+ - maps each option key to the pass that provided
      #   its effective value: +:original+, +:canonicalized+ or +:default+.
      class Resolution
        attr_reader :original_host, :matched_host, :host_name, :fallback,
                    :options, :option_sources

        def initialize(original_host:, matched_host:, host_name:, canonicalized:,
                       fallback:, options:, option_sources:)
          @original_host = original_host
          @matched_host = matched_host
          @host_name = host_name
          @canonicalized = canonicalized
          @fallback = fallback
          @options = options
          @option_sources = option_sources
        end

        def canonicalized?
          @canonicalized
        end

        def fallback?
          !@fallback.nil?
        end
      end

      # Default hostname resolver used during canonicalization. Any object
      # responding to +lookup(name)+ may be injected instead (see
      # Config.resolve); it must return nil when +name+ does not resolve, the
      # CNAME target as a String when one exists, or any other truthy value
      # when the name resolves without a CNAME.
      class DefaultResolver
        def lookup(name)
          require 'resolv'
          dns = Resolv::DNS.new
          begin
            return dns.getresource(name, Resolv::DNS::Resource::IN::CNAME).name.to_s
          rescue Resolv::ResolvError
            # no CNAME record; fall through to the address check
          end
          dns.getaddress(name)
          true
        rescue Resolv::ResolvError
          nil
        end
      end

      class << self
        @@default_files = %w[~/.ssh/config /etc/ssh_config /etc/ssh/ssh_config]
        # The following defaults follow the openssh client ssh_config defaults.
        # http://lwn.net/Articles/544640/
        # "hostbased" is off and "none" is not supported but we allow it since
        # it's used by some clients to query the server for allowed auth methods
        @@default_auth_methods = %w[none publickey password keyboard-interactive]

        # Returns an array of locations of OpenSSH configuration files
        # to parse by default.
        def default_files
          @@default_files.clone
        end

        def default_auth_methods
          @@default_auth_methods.clone
        end

        # Loads the configuration data for the given +host+ from all of the
        # given +files+ (defaulting to the list of files returned by
        # #default_files), translates the resulting hash into the options
        # recognized by Net::SSH, and returns them.
        def for(host, files = expandable_default_files, resolver: nil)
          resolve(host, files, resolver: resolver).options
        end

        # Resolves the configuration for +host+, performing hostname
        # canonicalization when the configuration requests it. +resolver+ may
        # be any object responding to +lookup(name)+ (see DefaultResolver);
        # when omitted, real DNS lookups are performed, but only if
        # canonicalization is actually enabled by the configuration.
        #
        # Returns a Resolution describing the original host name, the name
        # used for Host/Match matching, the final connection host name, the
        # translated options, and the pass each option value came from.
        def resolve(host, files = expandable_default_files, resolver: nil)
          files = Array(files)

          # First pass, evaluated as a pre-canonicalization parse: Match
          # +final+ and +canonical+ criteria are inactive here.
          prescan = files.inject({}) do |settings, file|
            load(file, host, settings, nil, stage: :original)
          end

          unless canonicalization_requested?(prescan, host)
            settings = files.inject({}) do |memo, file|
              load(file, host, memo, nil, stage: :final)
            end
            settings['host'] = host
            return build_resolution(host, settings, settings,
                                    canonicalized: false, fallback: nil)
          end

          pass1_snapshot = snapshot_settings(prescan)

          status, detail = canonicalize(host, canonical_domains(prescan),
                                        resolver, permitted_cname_rules(prescan))
          if status == :ok
            matched_host = detail
            fallback = nil
          else
            fallback_local = prescan.fetch('canonicalizefallbacklocal', true)
            unless fallback_local
              raise CanonicalizationError,
                    "hostname canonicalization failed for #{host}: #{detail}"
            end
            matched_host = host
            fallback = :local
          end

          # Second pass: re-read every file for the canonical name. Values
          # already obtained in the first pass keep precedence.
          settings = files.inject(prescan) do |memo, file|
            load(file, matched_host, memo, nil,
                 stage: :canonicalized, original_host: host)
          end
          %w[identityfile certificatefile].each do |key|
            next unless settings[key]

            # Values obtained in the first pass keep their leading position;
            # values appended by the second pass follow, without duplicates.
            pass1_values = pass1_snapshot[key] || []
            settings[key] = (pass1_values + (settings[key] - pass1_values)).uniq
          end
          settings['host'] = matched_host

          build_resolution(host, settings, pass1_snapshot,
                           canonicalized: status == :ok, fallback: fallback)
        end

        # Load the OpenSSH configuration settings in the given +file+ for the
        # given +host+. If +settings+ is given, the options are merged into
        # that hash, with existing values taking precedence over newly parsed
        # ones. Returns a hash containing the OpenSSH options. (See
        # #translate for how to convert the OpenSSH options into Net::SSH
        # options.)
        # +stage+ describes which canonicalization pass this load belongs to:
        # :original (pre-canonicalization), :canonicalized (the re-read after
        # canonicalization) or :final/nil (a single, final parse). It only
        # affects how Match +canonical+/+final+ criteria are evaluated.
        # +original_host+ is the host name before canonicalization, used by
        # the Match +originalhost+ criterion.
        def load(path, host, settings = {}, base_dir = nil, stage: nil,
                 original_host: nil)
          file = File.expand_path(path)
          base_dir ||= File.dirname(file)
          return settings unless File.readable?(file)

          globals = {}
          block_matched = false
          block_seen = false
          IO.foreach(file) do |line|
            next if line =~ /^\s*(?:#.*)?$/

            if line =~ /^\s*(\S+)\s*=(.*)$/
              key, value = $1, $2
            else
              key, value = line.strip.split(/\s+/, 2)
            end

            # silently ignore malformed entries
            next if value.nil?

            key.downcase!
            value = unquote(value)

            value = case value.strip
                    when /^\d+$/ then value.to_i
                    when /^no$/i then false
                    when /^yes$/i then true
                    else value
                    end

            if key == 'host'
              # Support "Host host1 host2 hostN".
              # See http://github.com/net-ssh/net-ssh/issues#issue/6
              negative_hosts, positive_hosts = value.to_s.split(/\s+/).partition { |h| h.start_with?('!') }

              # Check for negative patterns first. If the host matches, that overrules any other positive match.
              # The host substring code is used to strip out the starting "!" so the regexp will be correct.
              negative_matched = negative_hosts.any? { |h| host =~ pattern2regex(h[1..-1]) }

              if negative_matched
                block_matched = false
              else
                block_matched = positive_hosts.any? { |h| host =~ pattern2regex(h) }
              end

              block_seen = true
              settings[key] = host
            elsif key == 'match'
              block_matched = eval_match_conditions(
                value, host, settings,
                original_host: original_host || host,
                final: stage != :original,
                canonical: stage == :canonicalized
              )
              block_seen = true
            elsif !block_seen
              case key
              when 'identityfile', 'certificatefile'
                (globals[key] ||= []) << value
              when 'include'
                included_file_paths(base_dir, value).each do |file_path|
                  globals = load(file_path, host, globals, base_dir,
                                 stage: stage, original_host: original_host)
                end
              else
                globals[key] = value unless settings.key?(key)
              end
            elsif block_matched
              case key
              when 'identityfile', 'certificatefile'
                (settings[key] ||= []) << value
              when 'include'
                included_file_paths(base_dir, value).each do |file_path|
                  settings = load(file_path, host, settings, base_dir,
                                  stage: stage, original_host: original_host)
                end
              else
                settings[key] = value unless settings.key?(key)
              end
            end

            # ProxyCommand and ProxyJump override each other so they need to be tracked togeather
            %w[proxyjump proxycommand].each do |proxy_key|
              if (proxy_value = settings.delete(proxy_key))
                settings['proxy'] ||= [proxy_key, proxy_value]
              end
            end
          end

          globals.merge(settings) do |key, oldval, newval|
            case key
            when 'identityfile', 'certificatefile'
              oldval + newval
            else
              newval
            end
          end
        end

        # Given a hash of OpenSSH configuration options, converts them into
        # a hash of Net::SSH options. Unrecognized options are ignored. The
        # +settings+ hash must have Strings for keys, all downcased, and
        # the returned hash will have Symbols for keys.
        def translate(settings)
          auth_methods = default_auth_methods.clone
          (auth_methods << 'challenge-response').uniq!
          ret = settings.each_with_object({ auth_methods: auth_methods }) do |(key, value), hash|
            translate_config_key(hash, key.to_sym, value, settings)
          end
          merge_challenge_response_with_keyboard_interactive(ret)
        end

        # Filters default_files down to the files that are expandable.
        def expandable_default_files
          default_files.keep_if do |path|
            File.expand_path(path)
            true
          rescue ArgumentError
            false
          end
        end

        private

        def translate_verify_host_key(value)
          case value
          when false
            :never
          when true
            :always
          when 'accept-new'
            :accept_new
          end
        end

        def translate_keepalive(hash, value)
          if value && value.to_i > 0
            hash[:keepalive] = true
            hash[:keepalive_interval] = value.to_i
          else
            hash[:keepalive] = false
          end
        end

        TRANSLATE_CONFIG_KEY_RENAME_MAP = {
          bindaddress: :bind_address,
          compression: :compression,
          compressionlevel: :compression_level,
          certificatefile: :keycerts,
          connecttimeout: :timeout,
          forwardagent: :forward_agent,
          identitiesonly: :keys_only,
          identityagent: :identity_agent,
          globalknownhostsfile: :global_known_hosts_file,
          hostkeyalias: :host_key_alias,
          identityfile: :keys,
          fingerprinthash: :fingerprint_hash,
          port: :port,
          user: :user,
          checkhostip: :check_host_ip
        }.freeze
        def translate_config_key(hash, key, value, settings)
          case key
          when :stricthostkeychecking
            hash[:verify_host_key] = translate_verify_host_key(value)
          when :ciphers
            hash[:encryption] = value.split(/,/)
          when :hostbasedauthentication
            if value
              (hash[:auth_methods] << "hostbased").uniq!
            else
              hash[:auth_methods].delete("hostbased")
            end
          when :hostkeyalgorithms
            hash[:host_key] = value.split(/,/)
          when :hostname
            hash[:host_name] = value.gsub(/%h/, settings['host'])
          when :macs
            hash[:hmac] = value.split(/,/)
          when :serveralivecountmax
            hash[:keepalive_maxcount] = value.to_i if value
          when :serveraliveinterval
            translate_keepalive(hash, value)
          when :passwordauthentication
            if value
              (hash[:auth_methods] << 'password').uniq!
            else
              hash[:auth_methods].delete('password')
            end
          when :challengeresponseauthentication
            if value
              (hash[:auth_methods] << 'challenge-response').uniq!
            else
              hash[:auth_methods].delete('challenge-response')
            end
          when :kbdinteractiveauthentication
            if value
              (hash[:auth_methods] << 'keyboard-interactive').uniq!
            else
              hash[:auth_methods].delete('keyboard-interactive')
            end
          when :preferredauthentications
            hash[:auth_methods] = value.split(/,/) # TODO we should place to preferred_auth_methods rather than auth_methods
          when :proxy
            if (proxy = setup_proxy(*value))
              hash[:proxy] = proxy
            end
          when :pubkeyauthentication
            if value
              (hash[:auth_methods] << 'publickey').uniq!
            else
              hash[:auth_methods].delete('publickey')
            end
          when :rekeylimit
            hash[:rekey_limit] = interpret_size(value)
          when :sendenv
            multi_send_env = value.to_s.split(/\s+/)
            hash[:send_env] = multi_send_env.map { |e| Regexp.new pattern2regex(e).source, false }
          when :setenv
            hash[:set_env] = Shellwords.split(value.to_s).map { |e| e.split '=', 2 }.to_h
          when :numberofpasswordprompts
            hash[:number_of_password_prompts] = value.to_i
          when :canonicalizehostname
            hash[:canonicalize_hostname] = value.to_s == 'always' ? 'always' : value
          when :canonicaldomains
            hash[:canonical_domains] = value.to_s.split(/\s+/)
          when :canonicalizefallbacklocal
            hash[:canonicalize_fallback_local] = value
          when :canonicalizemaxdots
            hash[:canonicalize_max_dots] = value.to_i
          when :canonicalizepermittedcnames
            hash[:canonicalize_permitted_cnames] = value.to_s.split(/\s+/)
          when :userknownhostsfile
            hash[:user_known_hosts_file] = value.split(/\s+/)
          when *TRANSLATE_CONFIG_KEY_RENAME_MAP.keys
            hash[TRANSLATE_CONFIG_KEY_RENAME_MAP[key]] = value
          end
        end

        def setup_proxy(type, value)
          case type
          when 'proxycommand'
            if value !~ /^none$/
              require 'net/ssh/proxy/command'
              Net::SSH::Proxy::Command.new(value)
            end
          when 'proxyjump'
            require 'net/ssh/proxy/jump'
            Net::SSH::Proxy::Jump.new(value)
          end
        end

        # Converts an ssh_config pattern into a regex for matching against
        # host names.
        def pattern2regex(pattern)
          tail = pattern
          prefix = String.new
          while !tail.empty? do
            head, sep, tail = tail.partition(/[\*\?]/)
            prefix = prefix + Regexp.quote(head)
            case sep
            when '*'
              prefix += '.*'
            when '?'
              prefix += '.'
            when ''
            else
              fail "Unpexpcted sep:#{sep}"
            end
          end
          Regexp.new("^" + prefix + "$", true)
        end

        # Converts the given size into an integer number of bytes.
        def interpret_size(size)
          case size
          when /k$/i then size.to_i * 1024
          when /m$/i then size.to_i * 1024 * 1024
          when /g$/i then size.to_i * 1024 * 1024 * 1024
          else size.to_i
          end
        end

        def merge_challenge_response_with_keyboard_interactive(hash)
          if hash[:auth_methods].include?('challenge-response')
            hash[:auth_methods].delete('challenge-response')
            (hash[:auth_methods] << 'keyboard-interactive').uniq!
          end
          hash
        end

        def included_file_paths(base_dir, config_paths)
          tokenize_config_value(config_paths).flat_map do |path|
            Dir.glob(File.expand_path(path, base_dir)).select { |f| File.file?(f) }
          end
        end

        # Tokenize string into tokens.
        # A token is a word or a quoted sequence of words, separated by whitespaces.
        def tokenize_config_value(str)
          str.scan(/([^"\s]+)?(?:"([^"]+)")?\s*/).map(&:join)
        end

        def eval_match_conditions(condition, host, settings,
                                  original_host: host, final: true,
                                  canonical: false)
          # Not using `\s` for whitespace matching as canonical
          # ssh_config parser implementation (OpenSSH) has specific character set.
          # Ref: https://github.com/openssh/openssh-portable/blob/2581333d564d8697837729b3d07d45738eaf5a54/misc.c#L237-L239
          tokens = condition.split(/[ \t\r\n]+|(?<!=)=(?!=)/).reject(&:empty?)
          return true if tokens == ["all"]

          condition_matches = []
          until tokens.empty?
            kind = tokens.shift
            case kind.downcase
            when "all"
              raise "all cannot be mixed with other conditions"
            when "canonical"
              condition_matches << canonical
            when "final"
              condition_matches << final
            when "host", "originalhost"
              exprs = unquote(tokens.shift.to_s)
              target = kind.downcase == "host" ? host : original_host
              if exprs.start_with?('!')
                negated = true
                exprs = exprs[1..-1]
              else
                negated = false
              end
              condition_met = false
              exprs.split(",").each do |expr|
                condition_met = condition_met || target =~ pattern2regex(expr)
              end
              condition_matches << (true && negated ^ condition_met)
            else
              # Unsupported criteria never match, but still consume their
              # argument so following criteria are parsed correctly.
              tokens.shift
              # warn "net-ssh: Unsupported expr in Match block: #{kind}"
            end
          end

          !condition_matches.empty? && condition_matches.all?
        end

        def unquote(string)
          string =~ /^"(.*)"$/ ? Regexp.last_match(1) : string
        end

        # Whether the first-pass settings ask for hostname canonicalization
        # of +host+. Mirrors the OpenSSH rules: canonicalization is skipped
        # for proxied connections unless CanonicalizeHostname=always, and for
        # names with more dots than CanonicalizeMaxDots (default 1).
        def canonicalization_requested?(settings, host)
          mode = settings['canonicalizehostname']
          always = mode.is_a?(String) && mode.downcase == 'always'
          return false unless mode == true || always
          return false if !always && proxied?(settings)

          max_dots = settings['canonicalizemaxdots']
          max_dots = 1 if max_dots.nil?
          max_dots = max_dots.to_i
          return false if max_dots >= 0 && host.count('.') > max_dots

          !canonical_domains(settings).empty?
        end

        def canonical_domains(settings)
          settings['canonicaldomains'].to_s.split(/\s+/)
        end

        # ProxyCommand none disables proxying explicitly, so it does not
        # count as a proxied connection.
        def proxied?(settings)
          proxy = settings['proxy']
          return false unless proxy

          !(proxy[0] == 'proxycommand' && proxy[1].to_s.downcase == 'none')
        end

        def permitted_cname_rules(settings)
          settings['canonicalizepermittedcnames'].to_s.split(/\s+/)
        end

        # Tries each canonical domain in declaration order and returns
        # [:ok, canonical_name] for the first candidate that resolves (and,
        # when a CNAME is involved, is permitted), or [:error, reason] when
        # no domain produced a usable result.
        def canonicalize(host, domains, resolver, permitted_rules)
          resolver ||= DefaultResolver.new
          domains.each do |domain|
            candidate = "#{host}.#{domain}"
            result = resolver.lookup(candidate)
            next if result.nil?

            cname = result.is_a?(String) ? result : nil
            if cname && !cname_permitted?(candidate, cname, permitted_rules)
              next
            end

            return [:ok, cname || candidate]
          end
          [:error, :no_canonical_result]
        end

        # CanonicalizePermittedCNAMEs rules look like
        # +source_pattern:target_pattern1,target_pattern2+. When no rules are
        # declared, every CNAME target is permitted.
        def cname_permitted?(candidate, cname, rules)
          return true if rules.empty?

          rules.any? do |rule|
            source, targets = rule.split(':', 2)
            next false unless targets

            candidate =~ pattern2regex(source) &&
              targets.split(',').any? { |t| cname =~ pattern2regex(t) }
          end
        end

        def snapshot_settings(settings)
          settings.each_with_object({}) do |(key, value), copy|
            copy[key] = value.is_a?(Array) ? value.dup : value
          end
        end

        def build_resolution(original_host, settings, pass1_snapshot,
                             canonicalized:, fallback:)
          options = translate(settings)
          matched_host = settings['host']
          if canonicalized && !settings.key?('hostname')
            options[:host_name] = matched_host
          end
          option_sources = audit_option_sources(settings, pass1_snapshot)
          if canonicalized && !settings.key?('hostname')
            option_sources[:host_name] = :canonicalized
          end
          Resolution.new(
            original_host: original_host,
            matched_host: matched_host,
            host_name: options.fetch(:host_name, matched_host),
            canonicalized: canonicalized,
            fallback: fallback,
            options: options,
            option_sources: option_sources
          )
        end

        # Maps every translated option to the pass that provided its
        # effective value: a raw setting counts as :original when it was
        # already present (unchanged) after the first pass, and as
        # :canonicalized when the second pass introduced or changed it.
        def audit_option_sources(settings, pass1_snapshot)
          default_options = translate({})
          sources = {}
          settings.each do |raw_key, value|
            next if raw_key == 'host'

            translated = translate(raw_key => value,
                                   'host' => settings['host'].to_s)
            affected = translated.keys - default_options.keys
            if translated[:auth_methods] != default_options[:auth_methods]
              affected << :auth_methods
            end
            stage = if pass1_snapshot.key?(raw_key) && pass1_snapshot[raw_key] == value
                      :original
                    else
                      :canonicalized
                    end
            affected.each { |opt| sources[opt] ||= stage }
          end
          sources[:auth_methods] ||= :default
          sources
        end
      end
    end
  end
end
