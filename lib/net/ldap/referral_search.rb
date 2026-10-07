# -*- ruby encoding: utf-8 -*-

class Net::LDAP
  ##
  # The aggregated outcome of a referral-following search. Behaves like an
  # Enumerable of the collected Net::LDAP::Entry objects, and additionally
  # exposes everything the chaser learned while walking the referral graph:
  #
  # * +entries+   - every entry returned by every server, in the order the
  #   servers were visited. Entries from different servers are never
  #   deduplicated, even when they share a DN.
  # * +referrals+ - one Hash per referral URL that was discovered:
  #   <tt>{url:, depth:, status:}</tt> where status is one of +:followed+,
  #   +:skipped+ (denied by policy), +:cycle+, +:depth_limit+ or
  #   +:limit_exceeded+.
  # * +failures+  - one Hash per branch that did not complete:
  #   <tt>{url:, host:, port:, depth:, code:, message:}</tt>. The root
  #   search has a +nil+ url.
  # * +sources+   - one Hash per server that was searched:
  #   <tt>{url:, host:, port:, depth:, entry_count:}</tt>.
  #
  # +success?+ is only true when every branch completed without error; a
  # successful root search with failed referral branches is not a success.
  class ReferralSearchResult
    include Enumerable

    attr_reader :entries, :referrals, :failures, :sources

    def initialize
      @entries = []
      @referrals = []
      @failures = []
      @sources = []
    end

    def each(&block)
      entries.each(&block)
    end

    def to_a
      entries.dup
    end

    def success?
      failures.empty?
    end
  end

  ##
  # Chases LDAP referrals across servers on behalf of Net::LDAP#search when
  # the +:follow_referrals+ option is given.
  #
  # Both continuation references (SearchResultReference) and a final
  # referral (a SearchResultDone with result code 10) are followed. Each
  # referral URL is combined with the search that produced it using the RFC
  # 4516 field rules: any of base DN, scope, filter and attribute list that
  # the URL specifies overrides the corresponding search parameter, and any
  # field the URL omits is inherited unchanged.
  #
  # Every hop is authorized by the caller-supplied +:referral_policy+ proc,
  # which receives <tt>{url:, host:, port:, depth:}</tt> and returns:
  #
  # * +false+ or +nil+ to skip the referral,
  # * +true+ to follow it with an anonymous bind,
  # * an auth Hash (e.g. <tt>{method: :simple, username:, password:}</tt>)
  #   to follow it with those credentials.
  #
  # Without a policy, referrals are followed anonymously. The credentials of
  # the connection that received the referral are never reused for a
  # referred server unless the policy explicitly returns them.
  #
  # The graph walk is bounded by +:max_referral_depth+ (default 5) and
  # +:max_referrals+ (default 32, the total number of referrals followed).
  # Re-visiting an already-seen target (scheme, host, port, base, scope,
  # filter and attributes) is reported as a cycle and not followed again.
  #
  # Network access goes through +:connection_factory+, a callable receiving
  # <tt>(host, port, auth, scheme)</tt> and returning an object that
  # responds to +search(args)+ (yielding entries and referral entries) and
  # +get_operation_result+. The default factory builds a Net::LDAP for the
  # referred server.
  class ReferralSearch
    DEFAULT_MAX_DEPTH = 5
    DEFAULT_MAX_REFERRALS = 32

    # Options consumed by the chaser itself; never forwarded to the
    # per-server searches.
    CHASER_KEYS = [
      :follow_referrals, :referral_policy, :max_referral_depth,
      :max_referrals, :connection_factory,
    ].freeze

    def initialize(root_client, args = {}, encryption: nil)
      @root_client = root_client
      @args = args
      @encryption = encryption
      @max_depth = (args[:max_referral_depth] || DEFAULT_MAX_DEPTH).to_i
      @max_referrals = (args[:max_referrals] || DEFAULT_MAX_REFERRALS).to_i
      @policy = args[:referral_policy]
      @factory = args[:connection_factory] || method(:default_connection_factory)
    end

    def run(&block)
      @block = block
      @result = ReferralSearchResult.new
      @visited = {}
      @followed = 0

      root = root_node
      @visited[target_key(root[:target])] = true
      queue = [root]

      until queue.empty?
        node = queue.shift
        referrals = search_node(node)
        referrals.each { |url| process_referral(url, node, queue) }
      end

      @result
    end

    private

    def root_node
      {
        client: @root_client,
        depth: 0,
        url: nil,
        target: {
          scheme: @encryption ? "ldaps" : "ldap",
          host: @root_client.respond_to?(:host) ? @root_client.host : nil,
          port: @root_client.respond_to?(:port) ? @root_client.port : nil,
          search_args: search_args_from(@args),
        },
      }
    end

    def search_args_from(args)
      cleaned = args.reject { |key, _| CHASER_KEYS.include?(key) }
      cleaned[:return_referrals] = true
      cleaned
    end

    def search_node(node)
      referrals = []
      entry_count = 0

      begin
        node[:client].search(node[:target][:search_args]) do |entry|
          urls = entry[:search_referrals]
          if urls && !urls.empty?
            referrals.concat(urls)
          else
            entry_count += 1
            @result.entries << entry
            @block.call(entry) if @block
          end
        end
      rescue Net::LDAP::Error => e
        @result.failures << failure(node, Net::LDAP::ResultCodeOperationsError, e.message)
        return referrals
      end

      @result.sources << {
        url: node[:url],
        host: node[:target][:host],
        port: node[:target][:port],
        depth: node[:depth],
        entry_count: entry_count,
      }

      code, message = operation_status(node[:client])
      unless success_code?(code)
        @result.failures << failure(node, code, message)
      end

      referrals
    end

    def operation_status(client)
      op = client.get_operation_result
      message = op.respond_to?(:error_message) ? op.error_message : nil
      message = op.message if (message.nil? || message.empty?) && op.respond_to?(:message)
      [op.code.to_i, message]
    end

    def success_code?(code)
      code == Net::LDAP::ResultCodeReferral ||
        Net::LDAP::ResultCodesSearchSuccess.include?(code)
    end

    def failure(node, code, message)
      {
        url: node[:url],
        host: node[:target][:host],
        port: node[:target][:port],
        depth: node[:depth],
        code: code,
        message: message,
      }
    end

    def process_referral(url, parent, queue)
      depth = parent[:depth] + 1

      begin
        target_url = Net::LDAP::LdapUrl.parse(url)
        search_args = merge_search_args(parent[:target][:search_args], target_url)
      rescue Net::LDAP::Error => e
        @result.failures << {
          url: url, host: nil, port: nil, depth: depth,
          code: Net::LDAP::ResultCodeProtocolError, message: e.message,
        }
        return
      end

      target = {
        scheme: target_url.scheme,
        host: target_url.host,
        port: target_url.port,
        search_args: search_args,
      }

      if depth > @max_depth
        log_referral(url, depth, :depth_limit)
        return
      end

      if @visited[target_key(target)]
        log_referral(url, depth, :cycle)
        return
      end

      if @followed >= @max_referrals
        log_referral(url, depth, :limit_exceeded)
        return
      end

      auth = authorize(target_url, url, depth)
      unless auth
        log_referral(url, depth, :skipped)
        return
      end

      @visited[target_key(target)] = true
      @followed += 1
      log_referral(url, depth, :followed)

      queue << {
        client: @factory.call(target_url.host, target_url.port, auth, target_url.scheme),
        depth: depth,
        url: url,
        target: target,
      }
    end

    # RFC 4516 field rules: fields present in the URL override the
    # corresponding parameter of the search that produced the referral;
    # absent fields are inherited unchanged.
    def merge_search_args(parent_args, url)
      merged = parent_args.dup
      merged[:base] = url.dn if url.dn
      merged[:attributes] = url.attributes if url.attributes
      merged[:scope] = url.scope if url.scope
      merged[:filter] = Net::LDAP::Filter.construct(url.filter) if url.filter
      merged
    end

    def target_key(target)
      args = target[:search_args]
      [
        target[:scheme].to_s,
        target[:host].to_s.downcase,
        target[:port].to_i,
        args[:base].to_s,
        args[:scope].to_i,
        args[:filter].to_s,
        Array(args[:attributes]).map(&:to_s).sort,
      ]
    end

    # Asks the caller's policy whether a referral may be followed and with
    # which credentials. Defaults to an anonymous bind; the credentials of
    # the referring connection are never reused implicitly.
    def authorize(target_url, url, depth)
      decision =
        if @policy
          @policy.call(url: url, host: target_url.host, port: target_url.port, depth: depth)
        else
          true
        end

      case decision
      when nil, false
        nil
      when true
        { method: :anonymous }
      when Hash
        decision
      else
        raise ArgumentError,
              "referral policy must return false, true, or an auth Hash (got #{decision.inspect})"
      end
    end

    def log_referral(url, depth, status)
      @result.referrals << { url: url, depth: depth, status: status }
    end

    def default_connection_factory(host, port, auth, scheme)
      encryption = @encryption
      encryption ||= { method: :simple_tls } if scheme == "ldaps"
      Net::LDAP.new(host: host, port: port, auth: auth, encryption: encryption)
    end
  end
end
