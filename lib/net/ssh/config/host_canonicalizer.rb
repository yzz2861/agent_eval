require 'ipaddr'
require 'shellwords'

module Net
  module SSH
    class Config
      # Raised when hostname canonicalization is requested, the name could
      # not be canonicalized and CanonicalizeFallbackLocal is disabled.
      class CanonicalizationError < StandardError; end

      # Default host name resolver. It performs a real DNS lookup lazily
      # (only when no resolver was injected) and follows CNAME chains to
      # their final target, which must itself resolve to an address.
      class DefaultResolver
        def resolve(host)
          require 'resolv'

          canonical_name = follow_cname_chain(host)
          return nil if canonical_name.nil?

          Resolv::DNS.open { |dns| dns.getaddress(canonical_name) }
          canonical_name
        rescue Resolv::ResolvError
          nil
        end

        private

        def follow_cname_chain(host)
          seen = []
          candidate = host
          loop do
            return nil if seen.include?(candidate)
            seen << candidate

            begin
              cname = Resolv::DNS.open { |dns| dns.getresource(candidate, Resolv::DNS::Resource::IN::CNAME) }
            rescue Resolv::ResolvError
              return candidate
            end
            candidate = cname.name.to_s
          end
        end
      end

      # Implements the OpenSSH CanonicalizeHostname feature.
      #
      # The configuration is read in two passes:
      #
      # 1. The configuration is parsed for the host as supplied by the
      #    caller. Only this first pass determines whether and how
      #    canonicalization is performed.
      # 2. When a different canonical name is found, the configuration is
      #    parsed again with that name so Host/Match conditions and Include
      #    directives are evaluated against it. Options obtained in the
      #    first pass take precedence, exactly as with OpenSSH.
      class HostCanonicalizer
        # The host name as given to the configuration loader.
        attr_reader :original_host
        # The host name used for the second pass of Host/Match matching,
        # equal to original_host when canonicalization did not happen.
        attr_reader :canonical_host
        # The final settings hash (raw, downcased ssh_config keys).
        attr_reader :settings
        # Hash mapping raw option keys to the pass that supplied them:
        # :initial, :post_canonicalization or :both (for collected lists).
        attr_reader :option_sources
        # Whether canonicalization was requested by the first pass.
        attr_reader :requested
        # One of :canonicalized, :not_requested, :not_eligible,
        # :resolution_failed or :not_permitted.
        attr_reader :status
        # Array of attempted candidate records with the keys :candidate,
        # :canonical_name and :permitted.
        attr_reader :attempts

        def initialize(original_host, initial_settings, files, resolver: nil)
          @original_host = original_host
          @initial_settings = initial_settings
          @files = Array(files)
          @resolver = resolver || DefaultResolver.new
          @canonical_host = original_host
          @attempts = []
          @fall_back = false
          run
        end

        def canonicalized?
          status == :canonicalized
        end

        def fall_back?
          @fall_back
        end

        # The host that will actually be connected to, after a possible
        # HostName override from the merged settings.
        def connection_host
          host_name = settings['hostname']
          host_name ? host_name.gsub(/%h/, canonical_host) : canonical_host
        end

        private

        def run
          mode = canonical_mode(@initial_settings['canonicalizehostname'])
          if mode.nil?
            @requested = false
            @status = :not_requested
            finish(@initial_settings)
            return
          end
          @requested = true

          unless eligible?(mode)
            @status = :not_eligible
            finish(@initial_settings)
            return
          end

          domains = Array(@initial_settings['canonicaldomains'])
                              .flat_map { |value| Shellwords.split(value.to_s) }
                              .reject { |domain| domain.strip.empty? || domain == 'none' }
          permitted_rules = parse_permitted_cnames(@initial_settings['canonicalizepermittedcnames'])

          domains.each do |domain|
            candidate = build_candidate(@original_host, domain)
            canonical_name = call_resolver(candidate)
            record = { candidate: candidate, canonical_name: canonical_name, permitted: false }
            if canonical_name
              record[:permitted] = permitted_cname?(candidate, canonical_name, permitted_rules)
              @attempts << record
              if record[:permitted]
                @canonical_host = canonical_name
                if canonical_name == @original_host
                  @status = :canonicalized
                  finish(@initial_settings)
                else
                  @status = :canonicalized
                  second_pass
                end
                return
              end
            else
              @attempts << record
            end
          end

          if @initial_settings['canonicalizefallbacklocal'] == false
            @status = failure_status
            raise CanonicalizationError,
                  "hostname canonicalization failed for #{@original_host.inspect} and " \
                  "CanonicalizeFallbackLocal is disabled"
          end

          @fall_back = true
          @status = failure_status
          finish(@initial_settings)
        end

        def failure_status
          @attempts.any? { |record| record[:canonical_name] && !record[:permitted] } ? :not_permitted : :resolution_failed
        end

        def canonical_mode(value)
          case value
          when true, 'yes' then :yes
          when 'always' then :always
          end
        end

        def eligible?(mode)
          return false if ip_address?(@original_host)
          return false if @initial_settings.key?('hostname')
          return false if @initial_settings.key?('proxy')
          return false if @initial_settings.key?('proxyjump') || @initial_settings.key?('proxycommand')
          return false if mode == :yes && @original_host.count('.') > max_dots
          true
        end

        def max_dots
          value = @initial_settings['canonicalizemaxdots']
          value.is_a?(Integer) ? value : 1
        end

        def ip_address?(host)
          IPAddr.new(host)
          true
        rescue IPAddr::InvalidAddressError
          false
        end

        def build_candidate(host, domain)
          domain = domain.strip
          return host if host.end_with?('.')
          return host if host == domain || host.end_with?(".#{domain}")
          "#{host}.#{domain}"
        end

        def call_resolver(candidate)
          name = if @resolver.respond_to?(:resolve)
                   @resolver.resolve(candidate)
                 else
                   @resolver.call(candidate)
                 end
          return nil if name.nil?
          name = name.to_s.downcase
          name.empty? ? nil : name
        end

        def parse_permitted_cnames(value)
          text = value.to_s.strip
          text = '*:*' if text.empty?
          Shellwords.split(text).map do |spec|
            source, target = spec.split(':', 2)
            target = source if target.nil?
            { source: source.to_s, target: target.to_s }
          end
        end

        def permitted_cname?(candidate, canonical_name, rules)
          rules.each do |rule|
            next unless domain_list_match?(rule[:source], candidate)
            return domain_list_match?(rule[:target], canonical_name)
          end
          false
        end

        def domain_list_match?(list, name)
          list.split(',').any? { |pattern| domain_match?(pattern, name) }
        end

        # Matches ssh_config domain rules: the whole pattern must match,
        # with "*" and "?" as wildcards. A leading "." on the pattern
        # matches the bare domain as well as subdomains.
        def domain_match?(pattern, name)
          pattern = pattern.downcase
          name = name.downcase
          return true if pattern == '*' || pattern.empty?
          pattern = pattern[1..-1] if pattern.start_with?('.')
          source = pattern.chars.map do |char|
            case char
            when '*' then '.*'
            when '?' then '.'
            else Regexp.escape(char)
            end
          end.join
          name.match?(/\A#{source}\z/i)
        end

        def second_pass
          pass_two = {}
          @files.each do |file|
            pass_two = Config.load(file, canonical_host, pass_two, nil, @original_host)
          end
          @settings, @option_sources = merge_passes(@initial_settings, pass_two)
          @settings['host'] = canonical_host
          unless @settings.key?('hostname')
            @settings['hostname'] = canonical_host
            @option_sources['hostname'] = :canonical
          end
        end

        def finish(settings)
          @settings = settings
          @option_sources = {}
          settings.each_key do |key|
            @option_sources[key] = :initial unless key == 'host'
          end
        end

        def merge_passes(pass_one, pass_two)
          merged = {}
          sources = {}
          (pass_one.keys | pass_two.keys).each do |key|
            next if key == 'host'
            in_one = pass_one.key?(key)
            in_two = pass_two.key?(key)
            if in_one && in_two && collected_option?(key)
              merged[key] = Array(pass_one[key]).dup
              Array(pass_two[key]).each do |entry|
                merged[key] << entry unless merged[key].include?(entry)
              end
              sources[key] = :both
            elsif in_one
              merged[key] = copy_value(pass_one[key])
              sources[key] = :initial
            else
              merged[key] = copy_value(pass_two[key])
              sources[key] = :post_canonicalization
            end
          end
          [merged, sources]
        end

        def collected_option?(key)
          key == 'identityfile' || key == 'certificatefile'
        end

        def copy_value(value)
          value.is_a?(Array) ? value.dup : value
        end
      end
    end
  end
end
