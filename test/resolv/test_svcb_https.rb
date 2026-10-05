# frozen_string_literal: false
require 'test/unit'
require 'resolv'

class TestResolvSvcbHttps < Test::Unit::TestCase
  class MemoryDNS
    def initialize(records)
      @records = records
      @queries = []
    end

    attr_reader :queries

    def getresources(name, typeclass)
      name = Resolv::DNS::Name.create(name)
      @queries << [name, typeclass]
      @records.fetch([name, typeclass], [])
    end

    def use_ipv6?
      true
    end
  end

  ServiceEndpoint = Resolv::DNS::ServiceEndpoint

  def service_resolver(records, **options)
    memory_dns = MemoryDNS.new(records)
    resolver = ServiceEndpoint::Resolver.new(memory_dns, use_ipv6: true, **options)
    return resolver, memory_dns
  end

  def svcb(priority, target, *params)
    Resolv::DNS::Resource::IN::SVCB.new(priority, target, params)
  end

  def https(priority, target, *params)
    Resolv::DNS::Resource::IN::HTTPS.new(priority, target, params)
  end

  def a(address)
    Resolv::DNS::Resource::IN::A.new(address)
  end

  def aaaa(address)
    Resolv::DNS::Resource::IN::AAAA.new(address)
  end

  def candidate(address, source)
    ServiceEndpoint::AddressCandidate.new(Resolv::IPv4.create(address), source)
  rescue ArgumentError
    ServiceEndpoint::AddressCandidate.new(Resolv::IPv6.create(address), source)
  end

  # Wraps a RR in answer section
  def wrap_rdata(rrtype, rrclass, rdata)
    [
      "\x00\x00\x00\x00",  # ID/FLAGS
      [0, 1, 0, 0].pack('nnnn'),  # QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT
      "\x07example\x03com\x00",  # NAME
      [rrtype, rrclass, 0, rdata.bytesize].pack('nnNn'),  # TYPE/CLASS/TTL/RDLENGTH
      rdata,
    ].join.b
  end

  def test_svcparams
    params = Resolv::DNS::SvcParams.new([Resolv::DNS::SvcParam::Mandatory.new([1])])

    assert_equal 1, params.count

    params.add Resolv::DNS::SvcParam::NoDefaultALPN.new
    params.add Resolv::DNS::SvcParam::ALPN.new(%w[h2 h3])

    assert_equal 3, params.count

    assert_equal [1], params[:mandatory].keys
    assert_equal [1], params[0].keys

    assert_equal %w[h2 h3], params[:alpn].protocol_ids
    assert_equal %w[h2 h3], params[1].protocol_ids

    params.delete :mandatory
    params.delete :alpn

    assert_equal 1, params.count

    assert_nil params[:mandatory]
    assert_nil params[1]

    ary = params.each.to_a

    assert_instance_of Resolv::DNS::SvcParam::NoDefaultALPN, ary.first
  end

  def test_svcb
    rr = Resolv::DNS::Resource::IN::SVCB.new(0, 'example.com.')

    assert_equal 0, rr.priority
    assert rr.alias_mode?
    assert !rr.service_mode?
    assert_equal Resolv::DNS::Name.create('example.com.'), rr.target
    assert rr.params.empty?

    rr = Resolv::DNS::Resource::IN::SVCB.new(16, 'example.com.', [
      Resolv::DNS::SvcParam::ALPN.new(%w[h2 h3]),
    ])

    assert_equal 16, rr.priority
    assert !rr.alias_mode?
    assert rr.service_mode?

    assert_equal 1, rr.params.count
    assert_instance_of Resolv::DNS::SvcParam::ALPN, rr.params[:alpn]
  end

  def test_svcb_encode_order
    msg = Resolv::DNS::Message.new(0)
    msg.add_answer(
      'example.com.', 0,
      Resolv::DNS::Resource::IN::SVCB.new(16, 'foo.example.org.', [
        Resolv::DNS::SvcParam::ALPN.new(%w[h2 h3-19]),
        Resolv::DNS::SvcParam::Mandatory.new([4, 1]),
        Resolv::DNS::SvcParam::IPv4Hint.new(['192.0.2.1']),
      ])
    )

    expected = wrap_rdata 64, 1, "\x00\x10\x03foo\x07example\x03org\x00" +
      "\x00\x00\x00\x04\x00\x01\x00\x04" +
      "\x00\x01\x00\x09\x02h2\x05h3-19" +
      "\x00\x04\x00\x04\xc0\x00\x02\x01"

    assert_equal expected, msg.encode
  end

  ## Test vectors from [RFC9460]

  def test_alias_mode
    wire = wrap_rdata 65, 1, "\x00\x00\x03foo\x07example\x03com\x00"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 0, rr.priority
    assert_equal Resolv::DNS::Name.create('foo.example.com.'), rr.target
    assert_equal 0, rr.params.count

    assert_equal wire, msg.encode
  end

  def test_target_name_is_root
    wire = wrap_rdata 64, 1, "\x00\x01\x00"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 1, rr.priority
    assert_equal Resolv::DNS::Name.create('.'), rr.target
    assert_equal 0, rr.params.count

    assert_equal wire, msg.encode
  end

  def test_specifies_port
    wire = wrap_rdata 64, 1, "\x00\x10\x03foo\x07example\x03com\x00" +
      "\x00\x03\x00\x02\x00\x35"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 16, rr.priority
    assert_equal Resolv::DNS::Name.create('foo.example.com.'), rr.target
    assert_equal 1, rr.params.count
    assert_equal 53, rr.params[:port].port

    assert_equal wire, msg.encode
  end

  def test_generic_key
    wire = wrap_rdata 64, 1, "\x00\x01\x03foo\x07example\x03com\x00" +
      "\x02\x9b\x00\x05hello"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 1, rr.priority
    assert_equal Resolv::DNS::Name.create('foo.example.com.'), rr.target
    assert_equal 1, rr.params.count
    assert_equal 'hello', rr.params[:key667].value

    assert_equal wire, msg.encode
  end

  def test_two_ipv6hints
    wire = wrap_rdata 64, 1, "\x00\x01\x03foo\x07example\x03com\x00" +
      "\x00\x06\x00\x20" +
      ("\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" +
       "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x53\x00\x01")
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 1, rr.priority
    assert_equal Resolv::DNS::Name.create('foo.example.com.'), rr.target
    assert_equal 1, rr.params.count
    assert_equal [Resolv::IPv6.create('2001:db8::1'), Resolv::IPv6.create('2001:db8::53:1')],
      rr.params[:ipv6hint].addresses

    assert_equal wire, msg.encode
  end

  def test_ipv6hint_embedded_ipv4
    wire = wrap_rdata 64, 1, "\x00\x01\x07example\x03com\x00" +
      "\x00\x06\x00\x10\x20\x01\x0d\xb8\x01\x22\x03\x44\x00\x00\x00\x00\xc0\x00\x02\x21"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 1, rr.priority
    assert_equal Resolv::DNS::Name.create('example.com.'), rr.target
    assert_equal 1, rr.params.count
    assert_equal [Resolv::IPv6.create('2001:db8:122:344::192.0.2.33')],
      rr.params[:ipv6hint].addresses

    assert_equal wire, msg.encode
  end

  def test_mandatory_alpn_ipv4hint
    wire = wrap_rdata 64, 1, "\x00\x10\x03foo\x07example\x03org\x00" +
      "\x00\x00\x00\x04\x00\x01\x00\x04" +
      "\x00\x01\x00\x09\x02h2\x05h3-19" +
      "\x00\x04\x00\x04\xc0\x00\x02\x01"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 16, rr.priority
    assert_equal Resolv::DNS::Name.create('foo.example.org.'), rr.target
    assert_equal 3, rr.params.count
    assert_equal [1, 4], rr.params[:mandatory].keys
    assert_equal ['h2', 'h3-19'], rr.params[:alpn].protocol_ids
    assert_equal [Resolv::IPv4.create('192.0.2.1')], rr.params[:ipv4hint].addresses

    assert_equal wire, msg.encode
  end

  def test_alpn_comma_backslash
    wire = wrap_rdata 64, 1, "\x00\x10\x03foo\x07example\x03org\x00" +
      "\x00\x01\x00\x0c\x08f\\oo,bar\x02h2"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 16, rr.priority
    assert_equal Resolv::DNS::Name.create('foo.example.org.'), rr.target
    assert_equal 1, rr.params.count
    assert_equal ['f\oo,bar', 'h2'], rr.params[:alpn].protocol_ids

    assert_equal wire, msg.encode
  end

  ## For [RFC9461]

  def test_dohpath
    wire = wrap_rdata 64, 1, "\x00\x01\x03one\x03one\x03one\x03one\x00" +
      "\x00\x01\x00\x03\x02h2" +
      "\x00\x03\x00\x02\x01\xbb" +
      "\x00\x04\x00\x08\x01\x01\x01\x01\x01\x00\x00\x01" +
      "\x00\x06\x00\x20" +
      ("\x26\x06\x47\x00\x47\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x11" +
       "\x26\x06\x47\x00\x47\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x01") +
      "\x00\x07\x00\x10/dns-query{?dns}"
    msg = Resolv::DNS::Message.decode(wire)
    _, _, rr = msg.answer.first

    assert_equal 1, rr.priority
    assert_equal Resolv::DNS::Name.create('one.one.one.one.'), rr.target
    assert_equal 5, rr.params.count
    assert_equal ['h2'], rr.params[:alpn].protocol_ids
    assert_equal 443, rr.params[:port].port
    assert_equal [Resolv::IPv4.create('1.1.1.1'), Resolv::IPv4.create('1.0.0.1')],
      rr.params[:ipv4hint].addresses
    assert_equal [Resolv::IPv6.create('2606:4700:4700::1111'), Resolv::IPv6.create('2606:4700:4700::1001')],
      rr.params[:ipv6hint].addresses
    assert_equal '/dns-query{?dns}', rr.params[:dohpath].template

    assert_equal wire, msg.encode
  end

  def test_resolve_service_mode_endpoint
    rr = svcb(2, 'alt.example.org.',
      Resolv::DNS::SvcParam::ALPN.new(%w[h3 h2]),
      Resolv::DNS::SvcParam::Port.new(8443),
      Resolv::DNS::SvcParam::IPv4Hint.new(['192.0.2.20', '192.0.2.10']))
    resolver, dns = service_resolver(
      {
        [Resolv::DNS::Name.create('example.org.'), Resolv::DNS::Resource::IN::SVCB] => [rr],
        [Resolv::DNS::Name.create('alt.example.org.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.20')],
        [Resolv::DNS::Name.create('alt.example.org.'), Resolv::DNS::Resource::IN::AAAA] => [aaaa('2001:db8::20')],
      },
      protocols: %w[h2 http/1.1],
    )

    endpoint = resolver.each('example.org.', Resolv::DNS::Resource::IN::SVCB).first

    assert_equal Resolv::DNS::Name.create('alt.example.org.'), endpoint.target
    assert_equal 8443, endpoint.port
    assert_equal ['h2'], endpoint.protocols
    assert_equal 'h2', endpoint.protocol
    assert_equal [Resolv::IPv4.create('192.0.2.20'), Resolv::IPv6.create('2001:db8::20')], endpoint.addresses
    assert_equal [Resolv::IPv4.create('192.0.2.20')], endpoint.address_hints
    assert_equal [
      candidate('192.0.2.20', :ipv4hint),
      candidate('192.0.2.20', :A),
      candidate('2001:db8::20', :AAAA),
    ], endpoint.address_candidates
    assert_equal 2, endpoint.priority
    assert_same rr, endpoint.resource
    assert !endpoint.fallback?
    assert dns.queries.include?([Resolv::DNS::Name.create('alt.example.org.'), Resolv::DNS::Resource::IN::A])
    assert dns.queries.include?([Resolv::DNS::Name.create('alt.example.org.'), Resolv::DNS::Resource::IN::AAAA])
  end

  def test_follow_alias_mode_and_sort_priorities
    alias_rr = https(0, 'alias.example.com.')
    low = https(2, 'low.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(['h2']))
    high = https(1, 'high.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(['h3']))
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [alias_rr],
        [Resolv::DNS::Name.create('alias.example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [low, high],
        [Resolv::DNS::Name.create('low.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.21')],
        [Resolv::DNS::Name.create('high.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.31')],
      },
      protocols: %w[h3 h2 http/1.1],
      use_ipv6: false,
    )

    endpoints = resolver.each('example.com.').to_a

    assert_equal [
      Resolv::DNS::Name.create('high.example.com.'),
      Resolv::DNS::Name.create('low.example.com.'),
    ], endpoints.map(&:target)
    assert_equal [%w[h3], %w[h2]], endpoints.map(&:protocols)
  end

  def test_alias_loop
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('a.example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [https(0, 'b.example.com.')],
        [Resolv::DNS::Name.create('b.example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [https(0, 'a.example.com.')],
      },
      protocols: ['http/1.1'],
    )

    assert_raise(ServiceEndpoint::AliasLoopError) do
      resolver.each('a.example.com.').to_a
    end
  end

  def test_malformed_alias_mode_is_ignored
    malformed = https(0, 'ignored.example.com.',
      Resolv::DNS::SvcParam::Port.new(8443))
    service = https(1, 'service.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(['h2']))
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [malformed, service],
        [Resolv::DNS::Name.create('service.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.130')],
      },
      protocols: ['h2'],
      use_ipv6: false,
    )

    endpoint = resolver.each('example.com.').first

    assert_equal Resolv::DNS::Name.create('service.example.com.'), endpoint.target
  end

  def test_alias_depth_limit
    records = {}
    3.times do |i|
      records[[
        Resolv::DNS::Name.create("n#{i}.example.com."),
        Resolv::DNS::Resource::IN::HTTPS,
      ]] = [https(0, "n#{i + 1}.example.com.")]
    end
    resolver, = service_resolver(records, protocols: ['http/1.1'], max_aliases: 2)

    assert_raise(ServiceEndpoint::AliasDepthLimitError) do
      resolver.each('n0.example.com.').to_a
    end
  end

  def test_unknown_mandatory_param_makes_candidate_unusable
    unknown = Resolv::DNS::SvcParam::Generic.create(667).new('x')
    supported = https(1, 'supported.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(['h2']))
    unsupported = https(1, 'unsupported.example.com.',
      Resolv::DNS::SvcParam::Mandatory.new([667]),
      unknown,
      Resolv::DNS::SvcParam::ALPN.new(['h2']))
    resolver, dns = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [unsupported, supported],
        [Resolv::DNS::Name.create('supported.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.40')],
        [Resolv::DNS::Name.create('unsupported.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.50')],
      },
      protocols: ['h2'],
      use_ipv6: false,
    )

    endpoints = resolver.each('example.com.').to_a

    assert_equal [Resolv::DNS::Name.create('supported.example.com.')], endpoints.map(&:target)
    assert !dns.queries.include?([
      Resolv::DNS::Name.create('unsupported.example.com.'),
      Resolv::DNS::Resource::IN::A,
    ])
  end

  def test_unknown_optional_param_is_usable
    unknown = Resolv::DNS::SvcParam::Generic.create(667).new('x')
    rr = https(1, 'alt.example.com.',
      unknown,
      Resolv::DNS::SvcParam::ALPN.new(['h2']))
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [rr],
        [Resolv::DNS::Name.create('alt.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.60')],
      },
      protocols: ['h2'],
      use_ipv6: false,
    )

    assert_equal [Resolv::DNS::Name.create('alt.example.com.')], resolver.each('example.com.').map(&:target)
  end

  def test_alpn_filtering_and_no_default_alpn
    incompatible = https(1, 'incompatible.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(['h3']))
    no_default = https(2, 'no-default.example.com.',
      Resolv::DNS::SvcParam::NoDefaultALPN.new)
    compatible = https(3, 'compatible.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(%w[http/1.1 h2]))
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [incompatible, no_default, compatible],
        [Resolv::DNS::Name.create('compatible.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.70')],
      },
      protocols: %w[h2 http/1.1],
      use_ipv6: false,
    )

    endpoints = resolver.each('example.com.').to_a

    assert_equal [Resolv::DNS::Name.create('compatible.example.com.')], endpoints.map(&:target)
    assert_equal ['h2'], endpoints.first.protocols
  end

  def test_default_https_alpn
    rr = https(1, 'example.com.')
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [rr],
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.80')],
      },
      protocols: ['http/1.1'],
      use_ipv6: false,
    )

    endpoint = resolver.each('example.com.').first

    assert_equal 443, endpoint.port
    assert_equal ['http/1.1'], endpoint.protocols
  end

  def test_generic_svcb_requires_explicit_default_alpn_and_port
    rr = svcb(1, 'example.com.')
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::SVCB] => [rr],
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.110')],
      },
      protocols: ['h3'],
      default_protocols: ['h3'],
      port: 8443,
      use_ipv6: false,
    )

    endpoint = resolver.each('example.com.', Resolv::DNS::Resource::IN::SVCB).first

    assert_equal 8443, endpoint.port
    assert_equal ['h3'], endpoint.protocols
  end

  def test_dns_service_endpoint_entry_uses_memory_dns
    rr = https(1, 'alt.example.com.', Resolv::DNS::SvcParam::ALPN.new(['h2']))
    records = {
      [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [rr],
      [Resolv::DNS::Name.create('alt.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.120')],
    }
    dns = Resolv::DNS.new(nameserver: '0.0.0.0')
    dns.define_singleton_method(:getresources) do |name, typeclass|
      records.fetch([Resolv::DNS::Name.create(name), typeclass], [])
    end

    endpoint = dns.get_service_endpoint('example.com.', protocols: ['h2'], use_ipv6: false)

    assert_equal Resolv::DNS::Name.create('alt.example.com.'), endpoint.target
    assert_equal 443, endpoint.port
    assert_equal ['h2'], endpoint.protocols
  end

  def test_reliant_failure_does_not_fall_back
    resolver, = service_resolver({}, protocols: ['http/1.1'], use_ipv6: false)

    assert_raise(ServiceEndpoint::NoEndpointError) do
      resolver.each('example.com.').to_a
    end
  end

  def test_optional_failure_uses_explicit_fallback
    resolver, dns = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.90')],
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::AAAA] => [],
      },
      protocols: ['http/1.1'],
      fallback: :optional,
      use_ipv6: false,
    )

    endpoint = resolver.each('example.com.').first

    assert endpoint.fallback?
    assert_equal Resolv::DNS::Name.create('example.com.'), endpoint.target
    assert_equal 443, endpoint.port
    assert_equal ['http/1.1'], endpoint.protocols
    assert_equal [candidate('192.0.2.90', :A)], endpoint.address_candidates
    assert dns.queries.include?([Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS])
  end

  def test_unverified_address_hints_are_not_retained
    rr = https(1, 'alt.example.com.',
      Resolv::DNS::SvcParam::ALPN.new(['h2']),
      Resolv::DNS::SvcParam::IPv4Hint.new(['192.0.2.140']))
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [rr],
        [Resolv::DNS::Name.create('alt.example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.141')],
      },
      protocols: ['h2'],
      use_ipv6: false,
    )

    endpoint = resolver.each('example.com.').first

    assert_equal [Resolv::IPv4.create('192.0.2.141')], endpoint.addresses
    assert_empty endpoint.address_hints
  end

  def test_root_target_uses_original_name
    rr = https(1, '.', Resolv::DNS::SvcParam::ALPN.new(['h2']))
    resolver, = service_resolver(
      {
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::HTTPS] => [rr],
        [Resolv::DNS::Name.create('example.com.'), Resolv::DNS::Resource::IN::A] => [a('192.0.2.100')],
      },
      protocols: ['h2'],
      use_ipv6: false,
    )

    endpoint = resolver.each('example.com.').first

    assert_equal Resolv::DNS::Name.create('example.com.'), endpoint.target
  end
end
