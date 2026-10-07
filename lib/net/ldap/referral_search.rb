require 'uri'

class Net::LDAP
  class ReferralResult
    attr_reader :entries, :failures, :skipped, :root_result, :followed_branches

    def initialize(entries, root_result, failures, skipped, followed_branches)
      @entries = entries
      @root_result = root_result
      @failures = failures
      @skipped = skipped
      @followed_branches = followed_branches
    end

    def success?
      return false unless root_result_success?

      failures.empty?
    end

    def result_code
      root_result.respond_to?(:result_code) ? root_result.result_code : nil
    end

    def error_message
      root_result.respond_to?(:error_message) ? root_result.error_message : ""
    end

    private

    def root_result_success?
      code = result_code
      code == Net::LDAP::ResultCodeReferral ||
        Net::LDAP::ResultCodesSearchSuccess.include?(code)
    end
  end

  class ReferralSearch
    DEFAULT_MAX_DEPTH = 10
    DEFAULT_MAX_BRANCHES = 10

    SCOPES = {
      "base" => Net::LDAP::SearchScope_BaseObject,
      "one" => Net::LDAP::SearchScope_SingleLevel,
      "sub" => Net::LDAP::SearchScope_WholeSubtree,
    }.freeze

    def self.options(value, args)
      return nil unless value
      return normalize_options(args) if value == true
      unless value.respond_to?(:call)
        raise ArgumentError, "follow_referrals must be true or a callable policy"
      end

      options = normalize_options(args)
      options[:policy] = value
      options
    end

    def self.normalize_options(args)
      {
        max_depth: args.fetch(:max_referral_depth, DEFAULT_MAX_DEPTH).to_i,
        max_branches: args.fetch(:max_referral_branches, DEFAULT_MAX_BRANCHES).to_i,
        policy: nil,
      }
    end

    def initialize(root, args, options, connection_factory)
      @root = root
      @args = args.dup
      @args[:follow_referrals] = true
      @return_referrals = @args[:return_referrals] == true
      @max_depth = options[:max_depth]
      @max_branches = options[:max_branches]
      @policy = options[:policy] || method(:default_policy)
      @connection_factory = connection_factory
      @entries = []
      @failures = []
      @skipped = []
      @followed_branches = 0
    end

    def run
      root_target = target_options_for_root
      root_target[:client] = @root
      root_target[:depth] = 0
      root_target[:auth] = root_auth
      root_search_args = root_search_arguments
      root_result = search_target(root_target, 0, root_search_args)
      record_empty_final_referral(root_target, root_result)

      queue = Array(root_result.referral_uris).map do |uri|
        {
          uri: uri,
          depth: 1,
          source: nil,
          path: [key(root_target, root_search_args)],
        }
      end

      while (node = queue.shift)
        follow(node) do |child_uris, child_target, child_depth, child_key|
          child_path = node[:path] + [child_key]
          child_uris.each do |uri|
            queue << {
              uri: uri,
              depth: child_depth + 1,
              source: child_target[:uri],
              path: child_path,
            }
          end
        end
      end

      ReferralResult.new(@entries, root_result, @failures, @skipped, @followed_branches)
    end

    private

    def follow(node)
      depth = node[:depth]

      if depth > @max_depth
        record_failure(:max_depth_exceeded, node)
        return
      end

      target = parse_referral_uri(node[:uri])
      unless target
        record_failure(:invalid_referral_uri, node)
        return
      end

      target[:source] = node[:source]
      target[:depth] = depth

      begin
        target = authorize_target(target)
        unless target
          record_failure(:referral_denied, node)
          return
        end
      rescue StandardError => error
        record_failure(:policy_error, target, nil, error)
        return
      end

      search_args = search_args_for(target)
      target_key = key(target, search_args)

      if node[:path].include?(target_key)
        @skipped << failure_record(:referral_cycle, target, target_key)
        return
      end

      if @followed_branches >= @max_branches
        record_failure(:max_branches_exceeded, target, target_key)
        return
      end

      @followed_branches += 1
      result = search_target(target, depth, search_args)
      unless successful_result?(result)
        @failures << failure_record(:search_failed, target, target_key, nil, result)
        return
      end

      uris = Array(result.referral_uris)
      if result.result_code == Net::LDAP::ResultCodeReferral && uris.empty?
        @failures << failure_record(:empty_referral, target, target_key, nil, result)
        return
      end
      yield(uris, target, depth, target_key) if block_given?
    end

    def parse_referral_uri(uri_string)
      uri = URI.parse(uri_string)
      return nil unless uri.is_a?(URI::LDAP)

      parent = target_options_for_root
      host = uri.host.to_s.empty? ? parent[:host] : URI::DEFAULT_PARSER.unescape(uri.host)
      port =
        if (explicit_port_value = explicit_port(uri_string))
          explicit_port_value.to_i
        elsif host == parent[:host]
          parent[:port]
        else
          default_port(uri.scheme)
        end

      base, attribute_field, scope_field, filter_field = ldap_url_fields(uri_string)
      base = base.nil? ? @args[:base] : URI::DEFAULT_PARSER.unescape(base)
      scope = scope_from_field(scope_field)
      return nil unless scope_field.nil? || scope
      return nil if filter_field == ""
      filter = filter_field.nil? ? @args[:filter] : URI::DEFAULT_PARSER.unescape(filter_field)
      attributes = attributes_from_field(attribute_field)

      {
        uri: uri_string,
        scheme: uri.scheme,
        host: host,
        port: port,
        base: base,
        scope: scope,
        filter: filter,
        attributes: attributes,
        encryption: uri.scheme == "ldaps" ? { method: :simple_tls, tls_options: {} } : nil,
      }
    rescue URI::Error, ArgumentError, KeyError
      nil
    end

    def ldap_url_fields(uri_string)
      pattern = Regexp.new(
        '^[a-z][a-z0-9+.-]*://[^/]*?(?:/([^?]*))?(?:\?(.*))?$',
        Regexp::IGNORECASE,
      )
      match = pattern.match(uri_string)
      return nil unless match

      base, query = match.captures
      fields = split_ldap_query(query)
      [base, *Array.new(3) { |index| fields[index] }]
    end

    def split_ldap_query(query)
      return [] if query.nil?

      fields = query.split("?", 4)
      fields.concat(Array.new(3 - fields.length)) if query.end_with?("?")
      fields
    end

    def scope_from_field(scope_field)
      return @args[:scope] || Net::LDAP::SearchScope_WholeSubtree if scope_field.nil?
      return Net::LDAP::SearchScope_BaseObject if scope_field.empty?

      SCOPES[scope_field]
    end

    def attributes_from_field(attribute_field)
      return Array(@args[:attributes]) if attribute_field.nil?
      return [] if attribute_field.empty?

      attribute_field.split(",").map { |attribute| URI::DEFAULT_PARSER.unescape(attribute.strip) }
    end

    def explicit_port(uri_string)
      authority = uri_string.split("://", 2).last.to_s.split("/", 2).first.to_s
      query_start = authority.index("?")
      authority = authority[0, query_start] if query_start
      return nil unless authority.include?(":")

      port = authority.split(":", 2).last
      /\A\d+\z/.match?(port) ? port : nil
    end

    def default_port(scheme)
      scheme == "ldaps" ? URI::LDAPS::DEFAULT_PORT : URI::LDAP::DEFAULT_PORT
    end

    def authorize_target(target)
      decision = call_policy(target)
      return nil if decision.nil? || decision == false
      return target if decision == true
      return client_decision(target, decision) if decision.respond_to?(:search_once)
      return nil unless decision.is_a?(Hash)

      decision = symbolize_keys(decision)
      return nil if decision[:allowed] == false || decision[:allow] == false

      apply_policy_decision(target, decision)
    end

    def client_decision(target, client)
      target[:client] = client
      target[:auth] = client.instance_variable_get(:@auth) || { method: :anonymous }
      encryption = client.instance_variable_get(:@encryption)
      target[:encryption] = encryption if encryption
      target
    end

    def call_policy(target)
      @policy.call(target)
    end

    def default_policy(target, *)
      {
        host: target[:host],
        port: target[:port],
        auth: { method: :anonymous },
        encryption: target[:encryption],
      }
    end

    def search_args_for(target)
      args = @args.merge(
        base: target[:base],
        scope: target[:scope],
        filter: target[:filter],
        attributes: target[:attributes],
        auth: nil,
        ignore_server_caps: true,
        paged_searches_supported: false,
        follow_referrals: true,
        return_referrals: @return_referrals,
      )
      args[:auth] = target[:auth] if target.key?(:auth)
      args
    end

    def search_target(target, depth, search_args = nil)
      search_args ||= @args.merge(
        auth: nil,
        ignore_server_caps: true,
        paged_searches_supported: false,
        follow_referrals: true,
        return_referrals: @return_referrals,
      )
      search_args[:follow_referrals] = true

      client = target.key?(:client) ? target[:client] : @connection_factory.call(target)
      entries, result = client.search_once(search_args) do |entry|
        if entry.attribute_names == [:search_referrals]
          yield entry if block_given? && @return_referrals
        else
          @entries << entry
          yield entry if block_given?
        end
      end

      result
    rescue StandardError => error
      record_failure(:search_failed, target, nil, error)
      FailedResult.new(error)
    end

    def successful_result?(result)
      code = result.respond_to?(:result_code) ? result.result_code : nil
      code == Net::LDAP::ResultCodeReferral ||
        Net::LDAP::ResultCodesSearchSuccess.include?(code)
    end

    def target_options_for_root
      {
        uri: nil,
        scheme: root_scheme,
        host: @root.host,
        port: @root.port,
        base: @args[:base] || @root.base,
        scope: @args[:scope] || Net::LDAP::SearchScope_WholeSubtree,
        filter: @args[:filter],
        attributes: Array(@args[:attributes]),
      }
    end

    def root_scheme
      encryption = @root.instance_variable_get(:@encryption)
      encryption && encryption[:method] == :simple_tls ? "ldaps" : "ldap"
    end

    def root_auth
      @root.instance_variable_get(:@auth) || { method: :anonymous }
    end

    def root_search_arguments
      args = @args.merge(
        auth: root_auth,
        ignore_server_caps: true,
        paged_searches_supported: false,
        return_referrals: @return_referrals,
      )
      args[:follow_referrals] = true
      args
    end

    def record_empty_final_referral(target, result)
      return unless result.respond_to?(:result_code)
      return unless result.result_code == Net::LDAP::ResultCodeReferral
      return unless Array(result.referral_uris).empty?

      @failures << failure_record(
        :empty_referral,
        target,
        key(target, root_search_arguments),
        nil,
        result,
      )
    end

    def key(target, args)
      auth = args[:auth] || target[:auth] || {}
      [
        target[:scheme],
        target[:host],
        target[:port],
        target[:base],
        target[:scope],
        target[:filter].to_s,
        Array(target[:attributes]).map(&:to_s),
        auth[:method],
        auth[:username] || auth[:dn],
      ]
    end

    def record_failure(reason, target, target_key = nil, error = nil)
      @failures << failure_record(reason, target, target_key, error)
    end

    def failure_record(reason, target, target_key = nil, error = nil, result = nil)
      record = {
        reason: reason,
        uri: target[:uri],
        host: target[:host],
        port: target[:port],
        base: target[:base],
        depth: target[:depth],
        source: target[:source],
      }
      record[:key] = target_key if target_key
      record[:error] = error if error
      if result
        record[:result_code] = result.result_code
        record[:error_message] = result.error_message
      end
      record
    end

    def symbolize_keys(hash)
      hash.each_with_object({}) do |(key, value), result|
        result[key.to_sym] = value
      end
    end

    def apply_policy_decision(target, decision)
      if decision.key?(:auth) || decision.key?(:username)
        target[:auth] = policy_auth(decision)
      end
      target[:client] = decision[:client] if decision.key?(:client)
      target[:encryption] = decision[:encryption] if decision.key?(:encryption)
      target[:connect_timeout] = decision[:connect_timeout] if decision.key?(:connect_timeout)
      target
    end

    def policy_auth(decision)
      return decision[:auth] if decision.key?(:auth)

      {
        method: :simple,
        username: decision[:username],
        password: decision[:password],
      }
    end

    class FailedResult
      attr_reader :error

      def initialize(error)
        @error = error
      end

      def result_code
        nil
      end

      def error_message
        error.message
      end

      def referral_uris
        []
      end

      def success?
        false
      end
    end
  end
end
