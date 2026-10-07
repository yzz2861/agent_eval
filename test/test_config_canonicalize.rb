require_relative './common'
require 'net/ssh/config'
require 'net/ssh'
require 'tempfile'

class TestConfigCanonicalize < NetSSHTest
  # Injectable resolver double: maps candidate names to either true
  # (resolves, no CNAME) or a String (the CNAME target). Anything unmapped
  # does not resolve. Records every lookup so tests can assert exactly
  # which names were resolved without ever touching real DNS.
  class FakeResolver
    attr_reader :lookups

    def initialize(mapping = {})
      @mapping = mapping
      @lookups = []
    end

    def lookup(name)
      @lookups << name
      @mapping.fetch(name, nil)
    end
  end

  # Resolver that must never be called; used to prove canonicalization is
  # skipped (and no DNS traffic happens) when it should be.
  class ForbiddenResolver
    def lookup(name)
      raise "unexpected DNS lookup for #{name}"
    end
  end

  def test_canonicalizes_short_host_and_rematches_host_blocks
    data = <<~CONFIG
      Host web
        User webuser

      Host web.example.com
        Port 2200

      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    resolution = resolve_with_data(data, 'web', resolver)

    assert_equal 'web', resolution.original_host
    assert_equal 'web.example.com', resolution.matched_host
    assert_equal 'web.example.com', resolution.host_name
    assert resolution.canonicalized?
    refute resolution.fallback?
    assert_equal ['web.example.com'], resolver.lookups

    options = resolution.options
    assert_equal 'webuser', options[:user]
    assert_equal 2200, options[:port]
    assert_equal 'web.example.com', options[:host_name]
    assert_equal true, options[:canonicalize_hostname]
    assert_equal %w[example.com], options[:canonical_domains]

    assert_equal :original, resolution.option_sources[:user]
    assert_equal :canonicalized, resolution.option_sources[:port]
    assert_equal :canonicalized, resolution.option_sources[:host_name]
    assert_equal :default, resolution.option_sources[:auth_methods]
  end

  def test_first_pass_values_win_over_second_pass
    data = <<~CONFIG
      Host web
        User webuser
        Port 2222

      Host web.example.com
        User canonicaluser
        Port 2200

      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    resolution = resolve_with_data(data, 'web', resolver)

    assert_equal 'webuser', resolution.options[:user]
    assert_equal 2222, resolution.options[:port]
    assert_equal :original, resolution.option_sources[:user]
    assert_equal :original, resolution.option_sources[:port]
  end

  def test_follows_permitted_cname
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizePermittedCNAMEs *.example.com:*.internal.example.com

      Host web.internal.example.com
        User internaluser
    CONFIG
    resolver = FakeResolver.new('web.example.com' => 'web.internal.example.com')
    resolution = resolve_with_data(data, 'web', resolver)

    assert_equal 'web.internal.example.com', resolution.matched_host
    assert_equal 'web.internal.example.com', resolution.host_name
    assert_equal 'internaluser', resolution.options[:user]
    assert_equal %w[*.example.com:*.internal.example.com],
                 resolution.options[:canonicalize_permitted_cnames]
  end

  def test_unpermitted_cname_falls_back_to_original_host_by_default
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizePermittedCNAMEs *.example.com:*.other.example.net
    CONFIG
    resolver = FakeResolver.new('web.example.com' => 'web.internal.example.com')
    resolution = resolve_with_data(data, 'web', resolver)

    refute resolution.canonicalized?
    assert_equal :local, resolution.fallback
    assert_equal 'web', resolution.matched_host
    assert_equal 'web', resolution.host_name
    refute resolution.options.key?(:host_name)
  end

  def test_unpermitted_cname_raises_when_fallback_local_disabled
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
        CanonicalizePermittedCNAMEs *.example.com:*.other.example.net
    CONFIG
    resolver = FakeResolver.new('web.example.com' => 'web.internal.example.com')

    assert_raises(Net::SSH::Config::CanonicalizationError) do
      resolve_with_data(data, 'web', resolver)
    end
  end

  def test_resolution_failure_falls_back_or_raises
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com example.org
    CONFIG
    resolver = FakeResolver.new
    resolution = resolve_with_data(data, 'web', resolver)

    assert_equal %w[web.example.com web.example.org], resolver.lookups
    refute resolution.canonicalized?
    assert_equal :local, resolution.fallback
    assert_equal 'web', resolution.matched_host

    strict_data = data + "  CanonicalizeFallbackLocal no\n"
    assert_raises(Net::SSH::Config::CanonicalizationError) do
      resolve_with_data(strict_data, 'web', FakeResolver.new)
    end
  end

  def test_max_dots_disables_canonicalization
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolution = resolve_with_data(data, 'a.b.example.com', ForbiddenResolver.new)
    refute resolution.canonicalized?
    assert_equal 'a.b.example.com', resolution.matched_host

    raised = data + "  CanonicalizeMaxDots 3\n"
    resolver = FakeResolver.new('a.b.example.com.example.com' => true)
    resolution = resolve_with_data(raised, 'a.b.example.com', resolver)
    assert resolution.canonicalized?
    assert_equal 3, resolution.options[:canonicalize_max_dots]
  end

  def test_proxy_skips_canonicalization_unless_always
    data = <<~CONFIG
      Host *
        ProxyJump bastion
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolution = resolve_with_data(data, 'web', ForbiddenResolver.new)
    refute resolution.canonicalized?
    assert_instance_of Net::SSH::Proxy::Jump, resolution.options[:proxy]

    always = data.sub('CanonicalizeHostname yes', 'CanonicalizeHostname always')
    resolver = FakeResolver.new('web.example.com' => true)
    resolution = resolve_with_data(always, 'web', resolver)
    assert resolution.canonicalized?
    assert_equal 'always', resolution.options[:canonicalize_hostname]
    assert_instance_of Net::SSH::Proxy::Jump, resolution.options[:proxy]
  end

  def test_proxy_command_none_does_not_count_as_proxied
    data = <<~CONFIG
      Host *
        ProxyCommand none
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    resolution = resolve_with_data(data, 'web', resolver)
    assert resolution.canonicalized?
  end

  def test_match_canonical_final_and_originalhost
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com

      Match canonical
        Compression yes

      Match final host *.example.com
        ForwardAgent yes

      Match originalhost web
        User origuser
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    resolution = resolve_with_data(data, 'web', resolver)

    assert_equal true, resolution.options[:compression]
    assert_equal true, resolution.options[:forward_agent]
    assert_equal 'origuser', resolution.options[:user]
    assert_equal :canonicalized, resolution.option_sources[:compression]
    assert_equal true, resolution.options[:compression]
    assert_equal true, resolution.options[:forward_agent]
    assert_equal 'origuser', resolution.options[:user]
    assert_equal :canonicalized, resolution.option_sources[:compression]
    # originalhost matches the original name in every pass, so the value is
    # already obtained during the first pass.
    assert_equal :original, resolution.option_sources[:user]
  end

  def test_match_final_applies_and_canonical_does_not_when_disabled
    data = <<~CONFIG
      Host *
        CanonicalizeHostname no

      Match canonical
        Compression yes

      Match final
        ForwardAgent yes
    CONFIG
    resolution = resolve_with_data(data, 'web', ForbiddenResolver.new)

    refute resolution.options[:compression]
    assert_equal true, resolution.options[:forward_agent]
    assert_equal :original, resolution.option_sources[:forward_agent]
  end

  def test_hostname_directive_wins_over_canonical_name
    data = <<~CONFIG
      Host web
        HostName real.example.org

      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    resolution = resolve_with_data(data, 'web', resolver)

    assert resolution.canonicalized?
    assert_equal 'web.example.com', resolution.matched_host
    assert_equal 'real.example.org', resolution.host_name
    assert_equal 'real.example.org', resolution.options[:host_name]
    assert_equal :original, resolution.option_sources[:host_name]
  end

  def test_include_and_proxy_jump_survive_second_pass
    # NOTE: the sandbox used for development cannot Dir.glob under /tmp,
    # so the include fixture lives in a temporary dir inside the workspace.
    Dir.mktmpdir(nil, Dir.pwd) do |dir|
      included = File.join(dir, 'included')
      File.write(included, <<~CONFIG)
        Host web.example.com
          ProxyCommand ssh gateway
          User incuser
          IdentityFile ~/.ssh/id_included
      CONFIG
      main = File.join(dir, 'main')
      File.write(main, <<~CONFIG)
        Include #{included}

        Host web
          ProxyJump bastion
          IdentityFile ~/.ssh/id_main

        Host *
        Host web
          ProxyJump bastion
          IdentityFile ~/.ssh/id_main

        Host *
          CanonicalizeHostname always
          CanonicalDomains example.com
          CanonicalDomains example.com
      CONFIG

      resolver = FakeResolver.new('web.example.com' => true)
      resolution = Net::SSH::Config.resolve('web', [main], resolver: resolver)

      assert_instance_of Net::SSH::Proxy::Jump, resolution.options[:proxy]
      assert_equal 'incuser', resolution.options[:user]
      assert_equal :original, resolution.option_sources[:proxy]
      assert_equal :canonicalized, resolution.option_sources[:user]
      assert_equal %w[~/.ssh/id_main ~/.ssh/id_included],
                   resolution.options[:keys]
    end
  end

  def test_for_returns_translated_options_with_canonical_host_name
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    with_config_file(data) do |file|
      options = Net::SSH::Config.for('web', [file], resolver: resolver)
      assert_equal 'web.example.com', options[:host_name]
    end
  end

  def test_configuration_for_accepts_resolver
    data = <<~CONFIG
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
    CONFIG
    resolver = FakeResolver.new('web.example.com' => true)
    with_config_file(data) do |file|
      options = Net::SSH.configuration_for('web', [file], resolver: resolver)
      assert_equal 'web.example.com', options[:host_name]
    end
  end

  def test_without_canonicalize_directives_nothing_changes
    data = <<~CONFIG
      Host web
        User webuser
    CONFIG
    resolution = resolve_with_data(data, 'web', ForbiddenResolver.new)

    refute resolution.canonicalized?
    refute resolution.fallback?
    assert_equal 'web', resolution.matched_host
    assert_equal 'web', resolution.host_name
    assert_equal 'webuser', resolution.options[:user]
    refute resolution.options.key?(:host_name)
    assert_equal :original, resolution.option_sources[:user]
  end

  private

  def resolve_with_data(data, host, resolver)
    with_config_file(data) do |file|
      return Net::SSH::Config.resolve(host, [file], resolver: resolver)
    end
  end

  def with_config_file(data)
    Tempfile.open('config') do |f|
      f.write(data)
      f.close
      yield(f.path)
    end
  end
end
