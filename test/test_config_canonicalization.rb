require_relative './common'
require 'net/ssh/config'
require 'fileutils'
require 'tempfile'
require 'tmpdir'

class TestConfigCanonicalization < NetSSHTest
  # A deterministic, in-memory resolver: maps queried candidate names to the
  # canonical name they resolve to; no real DNS is ever touched.
  class FakeResolver
    attr_reader :queries

    def initialize(records)
      @records = records
      @queries = []
    end

    def resolve(host)
      @queries << host
      @records[host]
    end
  end

  def test_canonicalizes_short_host_with_declared_domain_suffix
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :canonicalized, result.status
    assert_equal 'box', result.original_host
    assert_equal 'box.example.com', result.canonical_host
    assert_equal 'box.example.com', result.connection_host
    assert_equal ['box.example.com'], resolver.queries

    options = Net::SSH::Config.for('box', [file], resolver: resolver)
    assert_equal 'box.example.com', options[:host_name]
  end

  def test_first_domain_that_resolves_to_permitted_target_wins
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.org example.com
        CanonicalizePermittedCNAMEs *.example.com:*.example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = FakeResolver.new(
      'box.example.org' => 'box.elsewhere.org',
      'box.example.com' => 'box.example.com'
    )

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :canonicalized, result.status
    assert_equal 'box.example.com', result.canonical_host
    assert_equal ['box.example.org', 'box.example.com'], resolver.queries
  end

  def test_second_pass_re_evaluates_match_canonical_conditions
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no

      Match canonical box.example.com
        Port 2200
        User canonical_user
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    options = Net::SSH::Config.translate(result.settings)

    assert_equal 2200, options[:port]
    assert_equal 'canonical_user', options[:user]
    assert_equal :post_canonicalization, result.option_sources['port']
  end

  def test_match_originalhost_is_evaluated_against_the_name_as_given
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no

      Match originalhost !other canonical !*.example.com
        Port 1
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    assert_equal :canonicalized, result.status
    assert_equal 1, result.settings['port']

    file_allow = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no

      Match originalhost box canonical box.example.com
        Port 2
    CONFIG
    result = Net::SSH::Config.canonicalize('box', [file_allow], resolver: resolver)
    assert_equal 2, result.settings['port']
  end

  def test_values_from_first_pass_take_precedence
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
        User first_pass

      Host box
        Port 1111

      Host box.example.com
        Port 2222
        User second_pass
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    options = Net::SSH::Config.translate(result.settings)

    assert_equal 1111, options[:port]
    assert_equal 'first_pass', options[:user]
    assert_equal :initial, result.option_sources['port']
    assert_equal :initial, result.option_sources['user']
  end

  def test_identity_files_from_both_passes_are_collected_with_first_pass_first
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
        IdentityFile ~/.ssh/first

      Host box.example.com
        IdentityFile ~/.ssh/second
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    options = Net::SSH::Config.translate(result.settings)

    assert_equal %w(~/.ssh/first ~/.ssh/second), options[:keys]
    assert_equal :both, result.option_sources['identityfile']
  end

  def test_include_in_second_pass_adds_new_options_without_overriding
    dir = File.expand_path("../tmp/ssh_include_#{object_id}", __dir__)
    FileUtils.mkdir_p(dir)
    begin
      included = File.join(dir, 'extra')
      File.write(included, <<~EXTRA)
        Host box.example.com
          Port 2222
          User from_include
      EXTRA
      file = config_file(<<~CONFIG)
        Host *
          CanonicalizeHostname yes
          CanonicalDomains example.com
          CanonicalizeFallbackLocal no
          User first_pass

        Host box.example.com
        Include #{included}
      CONFIG
      resolver = FakeResolver.new('box.example.com' => 'box.example.com')

      result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
      options = Net::SSH::Config.translate(result.settings)

      assert_equal 2222, options[:port]
      assert_equal 'first_pass', options[:user]
      assert_equal :post_canonicalization, result.option_sources['port']
      assert_equal :initial, result.option_sources['user']
    ensure
      FileUtils.remove_entry(dir)
    end
  end

  def test_host_name_from_second_pass_is_expanded_with_canonical_host
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    file2 = config_file(<<~CONFIG)
      Host box.example.com
        HostName internal.%h
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file, file2], resolver: resolver)

    assert_equal 'box.example.com', result.canonical_host
    assert_equal 'internal.box.example.com', result.connection_host
    options = Net::SSH::Config.for('box', [file, file2], resolver: resolver)
    assert_equal 'internal.box.example.com', options[:host_name]
  end

  def test_cname_outside_permitted_domains_is_rejected_and_raises_without_fallback
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizePermittedCNAMEs *.example.com:*.trusted.example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.evil.org')

    assert_raises(Net::SSH::Config::CanonicalizationError) do
      Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    end
  end

  def test_failure_falls_back_to_original_host_when_enabled
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal yes
        Port 1111
    CONFIG
    resolver = FakeResolver.new({})

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert result.fall_back?
    assert_equal :resolution_failed, result.status
    assert_equal 'box', result.canonical_host
    assert_equal 'box', result.connection_host
    assert_equal 1111, result.settings['port']
    assert_equal :initial, result.option_sources['port']

    options = Net::SSH::Config.for('box', [file], resolver: resolver)
    assert_equal 'box', options[:host_name]
  end

  def test_not_permitted_result_is_reported_on_fallback
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizePermittedCNAMEs *.example.com:*.trusted.example.com
        CanonicalizeFallbackLocal yes
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.evil.org')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :not_permitted, result.status
    assert result.fall_back?
    assert_equal 'box.example.com', result.attempts.first[:candidate]
    assert_equal 'box.evil.org', result.attempts.first[:canonical_name]
    refute result.attempts.first[:permitted]
  end

  def test_dotted_names_are_not_canonicalized_in_yes_mode_but_are_in_always_mode
    config_text = <<~CONFIG
      Host *
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    yes_file = config_file("CanonicalizeHostname yes\n" + config_text)
    always_file = config_file("CanonicalizeHostname always\n" + config_text)
    resolver = FakeResolver.new('host.sub.example.com' => 'host.sub.example.com')

    dotted_three = config_file("CanonicalizeHostname yes\n" + config_text)
    result_yes = Net::SSH::Config.canonicalize('host.sub', [yes_file], resolver: FakeResolver.new(
      'host.sub.example.com' => 'host.sub.example.com'
    ))
    assert_equal :canonicalized, result_yes.status

    result_too_many_dots = Net::SSH::Config.canonicalize('a.b.sub', [dotted_three], resolver: resolver)
    assert_equal :not_eligible, result_too_many_dots.status
    assert_equal [], resolver.queries

    result_always = Net::SSH::Config.canonicalize('host.sub', [always_file], resolver: FakeResolver.new(
      'host.sub.example.com' => 'host.sub.example.com'
    ))
    assert_equal :canonicalized, result_always.status
    assert_equal 'host.sub.example.com', result_always.canonical_host
  end

  def test_canonicalize_max_dots_controls_yes_mode_threshold
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalizeMaxDots 2
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = FakeResolver.new('host.sub.example.com' => 'host.sub.example.com')

    result = Net::SSH::Config.canonicalize('host.sub', [file], resolver: resolver)
    assert_equal :canonicalized, result.status
    assert_equal 'host.sub.example.com', result.canonical_host
  end

  def test_ip_literals_are_never_canonicalized
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname always
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = FakeResolver.new({})

    result = Net::SSH::Config.canonicalize('10.0.0.1', [file], resolver: resolver)

    assert_equal :not_eligible, result.status
    assert_equal [], resolver.queries
  end

  def test_explicit_hostname_skips_canonicalization
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
        HostName target.example.com
    CONFIG
    resolver = FakeResolver.new({})

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :not_eligible, result.status
    assert_equal 'target.example.com', result.connection_host
    assert_equal [], resolver.queries
  end

  def test_proxy_jump_skips_canonicalization_of_jump_target
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
        ProxyJump jumpbox
    CONFIG
    resolver = FakeResolver.new({})

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :not_eligible, result.status
    assert_equal [], resolver.queries
    options = Net::SSH::Config.for('box', [file], resolver: resolver)
    assert_instance_of Net::SSH::Proxy::Jump, options[:proxy]
  end

  def test_without_canonicalization_sources_remain_initial_and_names_agree
    file = config_file(<<~CONFIG)
      Host box
        Port 1111
    CONFIG
    resolver = FakeResolver.new({})

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :not_requested, result.status
    assert_equal 'box', result.original_host
    assert_equal 'box', result.canonical_host
    assert_equal 'box', result.connection_host
    assert_equal :initial, result.option_sources['port']
  end

  def test_callable_object_can_serve_as_resolver
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = lambda { |host| host == 'box.example.com' ? 'box.example.com' : nil }

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    assert_equal :canonicalized, result.status
    assert_equal 'box.example.com', result.connection_host
  end

  def test_proxy_jump_from_first_pass_takes_precedence
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
        ProxyJump first-jump

      Host box.example.com
        ProxyJump second-jump
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)
    options = Net::SSH::Config.translate(result.settings)

    assert_equal :not_eligible, result.status
    assert_instance_of Net::SSH::Proxy::Jump, options[:proxy]
    assert_equal 'first-jump', options[:proxy].jump_proxies
  end

  def test_missing_canonical_domains_fails_resolution_and_falls_back
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalizeFallbackLocal yes
    CONFIG
    resolver = FakeResolver.new({})

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :resolution_failed, result.status
    assert_equal [], result.attempts
    assert_equal 'box', result.connection_host
  end

  def test_synthetic_hostname_is_marked_with_canonical_source
    file = config_file(<<~CONFIG)
      Host *
        CanonicalizeHostname yes
        CanonicalDomains example.com
        CanonicalizeFallbackLocal no
    CONFIG
    resolver = FakeResolver.new('box.example.com' => 'box.example.com')

    result = Net::SSH::Config.canonicalize('box', [file], resolver: resolver)

    assert_equal :canonical, result.option_sources['hostname']
  end

  private

  def config_file(data)
    file = Tempfile.create('ssh_config')
    file.write(data)
    file.close
    @config_files ||= []
    @config_files << file.path
    file.path
  end

  def teardown
    (@config_files || []).each { |path| File.exist?(path) && File.unlink(path) }
  end
end
