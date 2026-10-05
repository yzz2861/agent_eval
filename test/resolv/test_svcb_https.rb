# frozen_string_literal: false
require 'test/unit'
require 'resolv'

class TestResolvSvcbHttps < Test::Unit::TestCase
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

  class MemoryDNS < Resolv::DNS
    def initialize
      @answers = Hash.new {|hash, key| hash[key] = []}
      @errors = {}
    end

    def add(name, typeclass, resource)
      @answers[[Name.create(name).to_s, typeclass]] << resource
    end

    def fail(name, typeclass, error = Resolv::ResolvError)
      @errors[[Name.create(name).to_s, typeclass]] = error
    end

    def getresources(name, typeclass)
      each_resource(name, typeclass).to_a
    end

    def each_resource(name, typeclass)
      return enum_for(:each_resource, name, typeclass) unless block_given?

      key = [Name.create(name).to_s, typeclass]
      raise @errors.fetch(key).new("memory DNS failure for #{name}") if @errors.key?(key)
      @answers.fetch(key, []).each {|resource| yield resource }
    end
  end

  def https(priority, target, *params)
    Resolv::DNS::Resource::IN::HTTPS.new(priority, target, params)
  end

  def svcb(priority, target, *params)
    Resolv::DNS::Resource::IN::SVCB.new(priority, target, params)
  end

  def add_ipv4(dns, name, *addresses)
    addresses.each do |address|
      dns.add(name, Resolv::DNS::Resource::IN::A,
              Resolv::DNS::Resource::IN::A.new(address))
    end
  end

  def add_ipv6(dns, name, *addresses)
    addresses.each do |address|
      dns.add(name, Resolv::DNS::Resource::IN::AAAA,
              Resolv::DNS::Resource::IN::AAAA.new(address))
    end
  end

  def test_service_endpoint_filters_alpn_and_preserves_address_sources
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(2, 'two.example.com',
                  Resolv::DNS::SvcParam::ALPN.new(%w[h3]),
                  Resolv::DNS::SvcParam::Port.new(8443)))
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'one.example.com',
                  Resolv::DNS::SvcParam::ALPN.new(%w[h2 http/1.1]),
                  Resolv::DNS::SvcParam::Port.new(9443),
                  Resolv::DNS::SvcParam::IPv4Hint.new(['192.0.2.10']),
                  Resolv::DNS::SvcParam::IPv6Hint.new(['2001:db8::10'])))
    add_ipv6(dns, 'one.example.com', '2001:db8::1')
    add_ipv4(dns, 'one.example.com', '198.51.100.1')

    endpoints = dns.get_service_endpoints('example.com', alpn: %w[h2])

    assert_equal 1, endpoints.length
    endpoint = endpoints.first
    assert_equal 'one.example.com', endpoint.target.to_s
    assert_equal 9443, endpoint.port
    assert_equal 'h2', endpoint.protocol
    assert_equal %w[h2], endpoint.protocols
    assert_equal ['2001:db8::1', '198.51.100.1'], endpoint.addresses.map(&:to_s)
    assert_equal ['2001:db8::10', '192.0.2.10'], endpoint.address_hints.map(&:to_s)
    assert_equal [
      [:address, '2001:db8::1'],
      [:address, '198.51.100.1'],
      [:ipv6hint, '2001:db8::10'],
      [:ipv4hint, '192.0.2.10'],
    ], endpoint.address_candidates.map {|candidate| [candidate.source, candidate.address.to_s] }
  end

  def test_service_endpoint_uses_default_https_alpn_and_port
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com'))
    add_ipv4(dns, 'target.example.com', '198.51.100.2')

    endpoint = dns.get_service_endpoint('example.com')

    assert_equal 443, endpoint.port
    assert_equal 'http/1.1', endpoint.protocol
    assert_equal ['http/1.1'], endpoint.protocols
  end

  def test_service_endpoint_without_alpn_only_matches_service_default
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com'))
    add_ipv4(dns, 'target.example.com', '198.51.100.11')

    assert_equal [], dns.get_service_endpoints('example.com', alpn: %w[h2])

    endpoint = dns.get_service_endpoint('example.com',
                                        alpn: %w[h2 http/1.1])
    assert_equal 'http/1.1', endpoint.protocol
  end

  def test_service_endpoint_requires_default_port_for_generic_svcb
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::SVCB,
            svcb(1, 'target.example.com'))
    add_ipv4(dns, 'target.example.com', '198.51.100.3')

    assert_equal [], dns.get_service_endpoints('example.com',
                                               Resolv::DNS::Resource::IN::SVCB)

    endpoint = dns.get_service_endpoint('example.com',
                                        Resolv::DNS::Resource::IN::SVCB,
                                        default_alpn: %w[h3],
                                        alpn: %w[h3], default_port: 443)
    assert_equal 443, endpoint.port
    assert_equal 'h3', endpoint.protocol
  end

  def test_service_endpoint_rejects_unknown_mandatory_parameter
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::Mandatory.new([667]),
                  Resolv::DNS::SvcParam::Generic.create(667).new('hello')))
    add_ipv4(dns, 'target.example.com', '198.51.100.4')

    assert_equal [], dns.get_service_endpoints('example.com')
  end

  def test_service_endpoint_unknown_mandatory_parameter_prevents_hint_use
    dns = MemoryDNS.new
    unknown = Resolv::DNS::SvcParam::Generic.create(667)
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::Mandatory.new([667]),
                  unknown.new('hello'),
                  Resolv::DNS::SvcParam::IPv4Hint.new(['192.0.2.30'])))
    add_ipv4(dns, 'target.example.com', '198.51.100.12')

    assert_equal [], dns.get_service_endpoints('example.com')
  end

  def test_service_endpoint_accepts_declared_optional_mandatory_parameter
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::Mandatory.new([7]),
                  Resolv::DNS::SvcParam::DoHPath.new('/dns-query{?dns}')))
    add_ipv4(dns, 'target.example.com', '198.51.100.5')

    endpoint = dns.get_service_endpoint('example.com', supported_params: [7])

    assert_equal 'target.example.com', endpoint.target.to_s
    assert_equal :service, endpoint.source
  end

  def test_service_endpoint_no_default_alpn_without_alpn_is_unusable
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::NoDefaultALPN.new))
    add_ipv4(dns, 'target.example.com', '198.51.100.6')

    assert_equal [], dns.get_service_endpoints('example.com')
  end

  def test_service_endpoint_follows_alias_chain
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(0, 'alias-1.example.com'))
    dns.add('alias-1.example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(0, 'alias-2.example.com'))
    dns.add('alias-2.example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::ALPN.new(%w[h2])))
    add_ipv4(dns, 'target.example.com', '198.51.100.7')

    endpoint = dns.get_service_endpoint('example.com', alpn: %w[h2])

    assert_equal 'target.example.com', endpoint.target.to_s
    assert_equal %w[h2], endpoint.protocols
  end

  def test_service_endpoint_detects_alias_loop
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(0, 'alias.example.com'))
    dns.add('alias.example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(0, 'example.com'))

    error = assert_raise(Resolv::DNS::ServiceBindingError) do
      dns.get_service_endpoint('example.com')
    end
    assert_match(/alias loop/, error.message)
  end

  def test_service_endpoint_enforces_alias_depth_limit
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(0, 'alias-0.example.com'))
    17.times do |index|
      dns.add("alias-#{index}.example.com", Resolv::DNS::Resource::IN::HTTPS,
              https(0, "alias-#{index + 1}.example.com"))
    end
    dns.add('alias-17.example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com'))

    assert_raise(Resolv::DNS::ServiceBindingError) do
      dns.get_service_endpoint('example.com')
    end
  end

  def test_service_endpoint_rejects_mixed_alias_and_service_records
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(0, 'alias.example.com'))
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com'))

    assert_raise(Resolv::DNS::ServiceBindingError) do
      dns.get_service_endpoint('example.com')
    end
  end

  def test_service_endpoint_no_implicit_origin_fallback
    dns = MemoryDNS.new
    add_ipv4(dns, 'example.com', '198.51.100.8')

    assert_equal [], dns.get_service_endpoints('example.com')
  end

  def test_service_endpoint_explicit_origin_fallback
    dns = MemoryDNS.new
    add_ipv4(dns, 'example.com', '198.51.100.9')

    endpoint = dns.get_service_endpoint('example.com', fallback: true)

    assert_nil endpoint.priority
    assert_equal :origin, endpoint.source
    assert_equal 'example.com', endpoint.target.to_s
    assert_equal 443, endpoint.port
    assert_equal 'http/1.1', endpoint.protocol
    assert_equal ['198.51.100.9'], endpoint.addresses.map(&:to_s)
  end

  def test_service_endpoint_explicit_origin_fallback_when_alpn_unsupported
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::ALPN.new(%w[h2])))
    add_ipv4(dns, 'example.com', '198.51.100.10')

    endpoint = dns.get_service_endpoint('example.com',
                                        alpn: %w[h3 http/1.1],
                                        fallback: true)

    assert_equal 'example.com', endpoint.target.to_s
    assert_equal 'http/1.1', endpoint.protocol
  end

  def test_service_endpoint_address_failure_is_explicit
    dns = MemoryDNS.new
    dns.add('example.com', Resolv::DNS::Resource::IN::HTTPS,
            https(1, 'target.example.com',
                  Resolv::DNS::SvcParam::IPv4Hint.new(['192.0.2.20'])))
    dns.fail('target.example.com', Resolv::DNS::Resource::IN::AAAA)
    dns.fail('target.example.com', Resolv::DNS::Resource::IN::A)

    assert_raise(Resolv::ResolvError) do
      dns.get_service_endpoint('example.com')
    end

    endpoint = dns.get_service_endpoint('example.com', address_fallback: true)

    assert_equal [], endpoint.addresses
    assert_equal ['192.0.2.20'], endpoint.address_hints.map(&:to_s)
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
end
