# frozen_string_literal: false
require 'test/unit'
require 'resolv'
require 'stringio'

class TestResolvDNSZone < Test::Unit::TestCase
  def dns_name(str)
    Resolv::DNS::Name.create(str)
  end

  def parse(text, **opts)
    Resolv::DNS::Zone.new(text, origin: opts.delete(:origin) || "example.org.",
                          ttl: opts.delete(:ttl),
                          filename: opts.delete(:filename),
                          resolver: opts.delete(:resolver)).to_a
  end

  def triple(name_s, ttl, resource)
    [dns_name(name_s), ttl, resource]
  end

  # ---- directives and basic records -------------------------------------

  def test_directives_and_basic_types
    zone = <<~ZONE
      $ORIGIN example.org.
      $TTL 3600
      @   IN SOA ns1 hostmaster 1 7200 3600 1209600 3600
      @   IN NS  ns1
      @   IN MX  10 mail
      ns1 IN A   192.0.2.1
      mail   A 192.0.2.2
      v6      AAAA 2001:db8::1
      www CNAME ns1
    ZONE
    records = parse(zone)
    assert_equal(7, records.length)
    assert_equal(triple("example.org.", 3600,
                        Resolv::DNS::Resource::IN::NS.new(dns_name("ns1.example.org."))),
                 records[1])
    assert_equal(dns_name("mail.example.org."), records[2][2].exchange)
    assert_equal(10, records[2][2].preference)
    assert_equal("192.0.2.1", records[3][2].address.to_s)
    assert_instance_of(Resolv::DNS::Resource::IN::AAAA, records[5][2])
    assert_equal(dns_name("ns1.example.org."), records[6][2].name)
  end

  def test_default_ttl_keyword_alias
    zone = "a IN A 1.2.3.4\n"
    z = Resolv::DNS::Zone.new(zone, origin: "e.", default_ttl: 42)
    assert_equal(42, z.to_a.first[1])
  end

  def test_ttl_and_class_in_either_order
    records = parse("a 100 IN A 1.2.3.4\nb IN 200 A 1.2.3.5\n")
    assert_equal(100, records[0][1])
    assert_equal(200, records[1][1])
    assert_equal("1.2.3.4", records[0][2].address.to_s)
  end

  def test_ttl_duration_units
    records = parse("a 1h30m IN A 1.2.3.4\nb 1w2d IN A 1.2.3.5\n")
    assert_equal(5400, records[0][1])
    assert_equal(604800 + 172800, records[1][1])
  end

  def test_explicit_ttl_overrides_default
    records = parse("$TTL 10\na 99 A 1.2.3.4\n")
    assert_equal(99, records[0][1])
  end

  def test_origin_updated_by_directive
    z = Resolv::DNS::Zone.new("$TTL 1\n$ORIGIN a.e.\nx IN A 1.1.1.1\n$ORIGIN b.e.\ny IN A 2.2.2.2\n")
    records = z.to_a
    assert_equal(dns_name("x.a.e."), records[0][0])
    assert_equal(dns_name("y.b.e."), records[1][0])
    assert(dns_name("b.e.").==(z.origin))
  end

  # ---- owner inheritance --------------------------------------------------

  def test_omitted_owner_is_inherited
    zone = <<~ZONE
      $TTL 5
      host IN A 1.2.3.4
           IN AAAA 2001:db8::1
           MX 10 mail
    ZONE
    records = parse(zone)
    assert_equal(3, records.length)
    records.each do |owner, _ttl, _r|
      assert_equal(dns_name("host.example.org."), owner)
    end
    assert_kind_of(Resolv::DNS::Resource::IN::MX, records[2][2])
  end

  def test_omitted_owner_at_start_is_an_error
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\n     IN A 1.2.3.4\n")
    end
    assert_equal(2, err.line)
  end

  # ---- relative and escaped names -----------------------------------------

  def test_relative_names_append_origin
    records = parse("$TTL 1\nfoo.bar IN A 1.2.3.4\n")
    assert_equal(dns_name("foo.bar.example.org."), records[0][0])
  end

  def test_at_means_origin
    records = parse("$TTL 1\n@ IN A 1.2.3.4\n")
    assert_equal(dns_name("example.org."), records[0][0])
  end

  def test_absolute_name_is_not_completed
    records = parse("$TTL 1\nx.other.com. IN A 1.2.3.4\n")
    assert_equal(dns_name("x.other.com."), records[0][0])
  end

  def test_escaped_dot_kept_in_label
    records = parse("$TTL 1\na\\.b IN A 1.2.3.4\n")
    assert_equal(%w[a.b example org], records[0][0].to_a.map(&:to_s))
  end

  def test_ddd_escape_in_name
    records = parse("$TTL 1\na\\065b IN A 1.2.3.4\n")
    # \DDD is decimal; 065 is ASCII 'A'.
    assert_equal("aAb", records[0][0].to_a.first.to_s)
  end

  def test_ddd_escape_decimal_value
    records = parse("$TTL 1\na\\053b IN A 1.2.3.4\n")
    assert_equal("a5b", records[0][0].to_a.first.to_s)
  end

  def test_soa_responsible_mailbox_escaped_dot
    records = parse("$TTL 1\n@ SOA ns admin\\.mail 1 2 3 4 5\n")
    soa = records[0][2]
    assert_equal(%w[admin.mail example org], soa.rname.to_a.map(&:to_s))
  end

  # ---- parentheses and comments -------------------------------------------

  def test_parenthesized_record_spans_lines
    zone = "$TTL 1\n@ IN SOA ( ns1 admin\n 1 2 3 4 5 )\n"
    records = parse(zone)
    soa = records[0][2]
    assert_equal(1, soa.serial)
    assert_equal(dns_name("ns1.example.org."), soa.mname)
  end

  def test_parenthesized_record_inherits_owner
    zone = "$TTL 1\na IN ( A 1.2.3.4 )\n( AAAA 2001:db8::1 )\n"
    records = parse(zone)
    assert_equal(2, records.length)
    assert_equal(records[0][0], records[1][0])
    assert_kind_of(Resolv::DNS::Resource::IN::AAAA, records[1][2])
  end

  def test_comments_full_line_and_trailing
    zone = <<~ZONE
      $TTL 1
      ; a whole line comment
      a IN A 1.2.3.4 ; trailing comment
      ; another
      b IN A 5.6.7.8
    ZONE
    records = parse(zone)
    assert_equal(["a", "b"], records.map {|n, _| n.to_a.first.to_s })
  end

  def test_semicolon_inside_quoted_string
    records = parse('$TTL 1' + "\n" +
                    't IN TXT "semi;colon"' + "\n")
    assert_equal(["semi;colon"], records[0][2].strings)
  end

  def test_unterminated_parenthesis
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\na IN ( A 1.2.3.4\n")
    end
    assert_match(/parenthesized/, err.message)
  end

  def test_unmatched_close_parenthesis
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\na IN A 1.2.3.4 )\n")
    end
    assert_match(/\)/, err.message)
  end

  def test_unterminated_quoted_string
    assert_raise(Resolv::DNS::Zone::ParseError) do
      parse('$TTL 1' + "\n" + 't TXT "abc' + "\n")
    end
  end

  # ---- TXT / character strings -------------------------------------------

  def test_txt_multiple_strings_and_escapes
    zone = '$TTL 1' + "\n" +
           't IN TXT "a b" "q\"x" "s\\\\e" "d\\053z"' + "\n"
    records = parse(zone)
    assert_equal(["a b", "q\"x", "s\\e", "d5z"], records[0][2].strings)
  end

  def test_txt_unquoted_string
    records = parse("$TTL 1\nt IN TXT plain\n")
    assert_equal(["plain"], records[0][2].strings)
  end

  def test_hinfo_two_strings
    records = parse('$TTL 1' + "\n" +
                    'h IN HINFO "Intel" "Linux"' + "\n")
    assert_equal("Intel", records[0][2].cpu)
    assert_equal("Linux", records[0][2].os)
  end

  # ---- include ------------------------------------------------------------

  def test_include_via_resolver_block
    files = {
      "main" => "$TTL 5\n$INCLUDE sub\nafter IN A 5.5.5.5\n",
      "sub"  => "$TTL 99\ninside IN A 6.6.6.6\n",
    }
    resolver = proc {|name, _origin| files.fetch(name) }
    z = Resolv::DNS::Zone.new(files["main"], filename: "main",
                              origin: "e.", &resolver)
    records = z.to_a
    assert_equal([dns_name("inside.e."), dns_name("after.e.")],
                 records.map {|n, _| n })
    # The included $TTL must not leak to the parent.
    assert_equal([99, 5], records.map {|_, ttl| ttl })
  end

  def test_include_origin_argument_passed_to_resolver
    seen = nil
    resolver = proc {|_name, origin| seen = origin; "x IN A 1.1.1.1\n" }
    Resolv::DNS::Zone.new("$TTL 1\n$INCLUDE child sub.e.\n",
                          origin: "e.", &resolver)
    assert_equal(dns_name("sub.e."), seen)
  end

  def test_include_optional_origin_scopes_names
    files = {
      "main" => "$TTL 1\n$INCLUDE c sub.e.\na IN A 2.2.2.2\n",
      "c" => "x IN A 1.1.1.1\n",
    }
    z = Resolv::DNS::Zone.new(files["main"], filename: "main",
                              origin: "e.") {|n| files.fetch(n) }
    assert_equal([dns_name("x.sub.e."), dns_name("a.e.")],
                 z.map {|n, _| n })
  end

  def test_include_scope_does_not_leak_origin_or_owner
    files = {
      "main" => "$TTL 1\n$ORIGIN main.e.\n$INCLUDE c\nrel IN A 9.9.9.9\n",
      "c"    => "$ORIGIN inc.e.\nz IN A 1.1.1.1\nmissing IN A 2.2.2.2\n",
    }
    z = Resolv::DNS::Zone.new(files["main"], filename: "main",
                              origin: "main.e.") {|n| files.fetch(n) }
    records = z.to_a
    # "rel" is completed with the parent origin, not the include's.
    assert_equal(dns_name("rel.main.e."), records.last[0])
    # The include's owner reset must not become the parent's last owner.
    assert_equal(dns_name("z.inc.e."), records[0][0])
    assert_equal(dns_name("missing.inc.e."), records[1][0])
    assert(dns_name("main.e.").==(z.origin))
  end

  def test_include_cycle_is_detected
    files = {
      "a" => "$TTL 1\n$INCLUDE b\n",
      "b" => "$INCLUDE c\n",
      "c" => "$INCLUDE a\n",
    }
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      Resolv::DNS::Zone.new(files["a"], filename: "a",
                            origin: "e.") {|n| files.fetch(n) }
    end
    assert_match(/cycle/, err.message)
    assert_match(/a -> b -> c -> a/, err.message)
    assert_equal("c", err.file)
  end

  def test_include_without_resolver_is_an_error
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\n$INCLUDE whatever\n")
    end
    assert_match(/no include resolver/, err.message)
    assert_equal(2, err.line)
  end

  def test_reader_does_not_access_filesystem
    # No resolver, and the include name looks like a path; the reader must
    # not attempt to open it itself.
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\n$INCLUDE /etc/passwd\n")
    end
    assert_match(/no include resolver/, err.message)
  end

  def test_include_resolver_may_name_file_for_errors
    files = {"named" => ["$TTL 1\n", "bad IN NOTATYPE x\n"].join}
    resolver = proc {|_| [files["named"], "custom-name"] }
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      Resolv::DNS::Zone.new("$TTL 1\n$INCLUDE named\n",
                            origin: "e.", &resolver)
    end
    assert_equal("custom-name", err.file)
  end

  def test_include_accepts_io_like_source
    io = StringIO.new("$TTL 1\nx IN A 1.2.3.4\n")
    z = Resolv::DNS::Zone.new(StringIO.new("$TTL 1\n$INCLUDE io\n"),
                              origin: "e.") { io }
    assert_equal([dns_name("x.e.")], z.map {|n, _| n })
  end

  # ---- RFC 3597 generic records -------------------------------------------

  def test_unknown_type_kept_generic
    records = parse("$TTL 1\nh IN TYPE45000 # 5 0102030405\n")
    resource = records[0][2]
    assert_kind_of(Resolv::DNS::Resource::Generic, resource)
    assert_equal(45000, resource.class::TypeValue)
    assert_equal(1, resource.class::ClassValue)
    assert_equal("\x01\x02\x03\x04\x05".b, resource.data)
    assert_equal(1, records[0][1])
  end

  def test_generic_non_in_class
    records = parse("$TTL 1\nhc CLASS3 TYPE99 # 3 aabbcc\n")
    resource = records[0][2]
    assert_equal(99, resource.class::TypeValue)
    assert_equal(3, resource.class::ClassValue)
    assert_equal("\xaa\xbb\xcc".b, resource.data)
  end

  def test_generic_zero_rdata
    records = parse("$TTL 1\nh IN TYPE1099 # 0\n")
    assert_equal("", records[0][2].data)
  end

  def test_generic_rdlength_mismatch
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\nh IN TYPE45000 # 3 aabb\n")
    end
    assert_match(/rdlength/, err.message)
  end

  def test_known_type_cannot_use_generic_form
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\nh IN A # 0\n")
    end
    assert_match(/generic/, err.message)
  end

  def test_unknown_mnemonic_is_an_error
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\nh IN BOGUSTYPE x\n")
    end
    assert_match(/unknown record type/, err.message)
  end

  def test_generic_roundtrip_wire
    wire = "\x01\x02\x03".b
    records = parse("$TTL 1\nh IN TYPE60000 # 3 010203\n")
    encoded = Resolv::DNS::Message::MessageEncoder.new do |m|
      records[0][2].encode_rdata(m)
    end.to_s
    assert_equal(wire, encoded)
  end

  # ---- concrete record types ----------------------------------------------

  def test_srv
    records = parse("$TTL 1\ns IN SRV 10 20 443 target\n")
    srv = records[0][2]
    assert_equal([10, 20], [srv.priority, srv.weight])
    assert_equal(443, srv.port)
    assert_equal(dns_name("target.example.org."), srv.target)
  end

  def test_caa
    records = parse('$TTL 1' + "\n" +
                    'ca IN CAA 0 issue "ca.example"' + "\n")
    caa = records[0][2]
    assert_equal(0, caa.flags)
    assert_equal("issue", caa.tag)
    assert_equal("ca.example", caa.value)
  end

  def test_caa_critical_flag
    records = parse("$TTL 1\nca IN CAA 128 iodef \"mailto:x@y\"\n")
    caa = records[0][2]
    assert_equal(0x80, caa.flags)
    assert(caa.critical?)
  end

  def test_minfo
    records = parse("$TTL 1\nm IN MINFO rmail email\n")
    minfo = records[0][2]
    assert_equal(dns_name("rmail.example.org."), minfo.rmailbx)
    assert_equal(dns_name("email.example.org."), minfo.emailbx)
  end

  def test_ptr_and_ns
    records = parse("$TTL 1\n1 IN PTR host\n")
    assert_equal(dns_name("host.example.org."), records[0][2].name)
  end

  def test_wks_port_bitmap
    records = parse("$TTL 1\nw IN WKS 192.0.2.1 6 25 80\n")
    wks = records[0][2]
    assert_equal(6, wks.protocol)
    bits = wks.bitmap.unpack1("B*")
    assert_equal(?1, bits[25])
    assert_equal(?1, bits[80])
    assert_equal(?0, bits[26])
  end

  def test_https_service_binding
    zone = '$TTL 1' + "\n" +
           's IN HTTPS 1 . alpn="h2,h3" port=443 no-default-alpn ' +
           'ipv4hint=192.0.2.1 dohpath=/doh mandatory=alpn,port' + "\n"
    records = parse(zone)
    https = records[0][2]
    assert_kind_of(Resolv::DNS::Resource::IN::HTTPS, https)
    assert_equal(1, https.priority)
    assert_equal(dns_name("."), https.target)
    assert_equal(%w[h2 h3], https.params[:alpn].protocol_ids)
    assert_equal(443, https.params[:port].port)
    assert_equal("192.0.2.1", https.params[:ipv4hint].addresses.first.to_s)
    assert_equal("/doh", https.params[:dohpath].template)
    assert_equal([1, 3], https.params[:mandatory].keys)
  end

  def test_svcb_generic_key_value
    zone = "$TTL 1\ns IN SVCB 1 . key68=\\x00\n"
    records = parse(zone)
    param = records[0][2].params[68]
    assert_equal("\x00\x01".b, param.value)
  end

  def test_loc
    zone = "$TTL 1\nl IN LOC 52 14 05.000 N 0 05 59.000 W 10m 20m 2m 0.5m\n"
    records = parse(zone)
    loc = records[0][2]
    assert_kind_of(Resolv::DNS::Resource::LOC, loc)
    assert_match(/N/, loc.latitude.to_s)
    assert_match(/W/, loc.longitude.to_s)
  end

  # ---- errors include position and record --------------------------------

  def test_error_reports_file_line_column_and_record
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\na IN A not-an-ip\n", filename: "db.zone")
    end
    assert_equal("db.zone", err.file)
    assert_equal(2, err.line)
    assert_kind_of(Integer, err.column)
    assert_equal("a IN A not-an-ip", err.record)
  end

  def test_missing_ttl_is_an_error
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("a IN A 1.2.3.4\n", origin: "e.")
    end
    assert_match(/TTL/, err.message)
  end

  def test_unknown_directive
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$BOGUS x\n")
    end
    assert_match(/unknown directive/, err.message)
  end

  def test_bad_ip_address
    assert_raise(Resolv::DNS::Zone::ParseError) do
      parse("$TTL 1\na IN A 999.1.1.1\n")
    end
  end

  # ---- enumeration --------------------------------------------------------

  def test_enumerator_and_enumerable
    z = Resolv::DNS::Zone.new("$TTL 1\na IN A 1.1.1.1\nb IN A 2.2.2.2\n",
                              origin: "e.")
    enum = z.each_resource
    assert_kind_of(Enumerator, enum)
    assert_equal(2, z.count)
    assert_equal(2, z.map {|_| 1 }.sum)
  end

  def test_each_is_alias
    z = Resolv::DNS::Zone.new("$TTL 1\na IN A 1.1.1.1\n", origin: "e.")
    assert_equal(1, z.each.count)
  end

  def test_resource_ttl_accessor
    records = parse("$TTL 77\na IN A 1.1.1.1\n")
    assert_equal(77, records[0][2].ttl)
  end

  # ---- input variants -----------------------------------------------------

  def test_crlf_line_endings
    records = parse("$TTL 1\r\na IN A 1.2.3.4\r\n     IN AAAA 2001:db8::1\r\n")
    assert_equal(2, records.length)
    assert_equal(records[0][0], records[1][0])
  end

  def test_frozen_input
    source = ("$TTL 1\n" "a IN A 1.2.3.4\n").freeze
    z = Resolv::DNS::Zone.new(source, origin: "e.")
    assert_equal(1, z.count)
  end

  def test_io_source
    z = Resolv::DNS::Zone.new(StringIO.new("$TTL 1\na IN A 1.2.3.4\n"),
                              origin: "e.")
    assert_equal("1.2.3.4", z.to_a.first[2].address.to_s)
  end

  def test_nested_includes_keep_scopes_isolated
    files = {
      "top" => "$TTL 10\n$ORIGIN top.e.\n$INCLUDE a\n" \
               "$ORIGIN after.top.e.\nx IN A 1.1.1.1\n",
      "a" => "$TTL 20\n$ORIGIN a.top.e.\n$INCLUDE b\na1 IN A 2.2.2.2\n",
      "b" => "$TTL 30\n$ORIGIN b.a.top.e.\nb1 IN A 3.3.3.3\n",
    }
    z = Resolv::DNS::Zone.new(files["top"], filename: "top") {|n| files[n] }
    names_and_ttls = z.map {|name, ttl, _| [name.to_s, ttl] }
    assert_equal([["b1.b.a.top.e", 30],
                  ["a1.a.top.e", 20],
                  ["x.after.top.e", 10]], names_and_ttls)
    assert_equal(10, z.ttl)
  end

  def test_include_origin_chain_for_nested_cycle
    files = {
      "a" => "$TTL 1\n$INCLUDE b\n",
      "b" => "$INCLUDE c\n",
      "c" => "$INCLUDE b\n",
    }
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      Resolv::DNS::Zone.new(files["a"], filename: "a",
                            origin: "e.") {|n| files[n] }
    end
    assert_equal("c", err.file)
    assert_match(/b -> c -> b/, err.message)
  end

  def test_include_resolver_failure_is_wrapped
    err = assert_raise(Resolv::DNS::Zone::ParseError) do
      Resolv::DNS::Zone.new("$TTL 1\n$INCLUDE nope\n", origin: "e.") do
        raise Errno::ENOENT, "nope"
      end
    end
    assert_match(/nope/, err.message)
    assert_equal(2, err.line)
  end

  def test_ttl_is_stored_on_resource
    z = Resolv::DNS::Zone.new("$TTL 42\na IN A 1.2.3.4\n", origin: "e.")
    assert_equal(42, z.to_a.first[2].ttl)
  end

end
