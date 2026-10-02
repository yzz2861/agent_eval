require_relative 'test_helper'

describe 'tilt/registry' do
  FakeAlpha = Class.new
  FakeBeta = Class.new
  FakeGamma = Class.new

  def build_registry(ext = 'fake')
    mapping = Tilt::Mapping.new
    mapping.register_lazy('Tilt::RegistryFakeAlpha', 'fake_alpha', ext)
    mapping.register_lazy('Tilt::RegistryFakeBeta', 'fake_beta', ext)
    mapping
  end

  def build_named_registry(alpha, beta, ext = 'fake')
    build_named_registry_on(alpha, beta, ext, Tilt::Mapping.new)
  end

  def build_named_registry_on(alpha, beta, ext, mapping)
    mapping.register_lazy(alpha, 'fake_alpha', ext)
    mapping.register_lazy(beta, 'fake_beta', ext)
    mapping
  end

  def without_fake_constants
    yield
  ensure
    names = [
      :RegistryFakeAlpha, :RegistryFakeBeta, :RegistryFakeGamma,
      :RegistryAppOneAlpha, :RegistryAppOneBeta,
      :RegistryAppTwoAlpha, :RegistryAppTwoBeta
    ]
    names.each do |name|
      Tilt.send(:remove_const, name) if Tilt.const_defined?(name, false)
    end
  end

  def stub_require(mapping, loader)
    mapping.define_singleton_method(:require) do |file|
      loader.call(file)
    end
  end

  it 'creates an independent snapshot of the global configuration' do
    global = Tilt.default_mapping
    registry = Tilt.registry

    global_order = global.candidates('md').map(&:first)
    registry.promote(global_order.last, 'md')

    refute_empty global_order
    assert_equal global_order, global.candidates('md').map(&:first)
    assert_equal global_order.last, registry.candidate_order('md').first.class_name
  end

  it 'keeps duplicates independent after successful lazy loading' do
    without_fake_constants do
      registry = build_named_registry_on('Tilt::RegistryAppOneAlpha', 'Tilt::RegistryAppOneBeta', 'fake', Tilt.registry)
      other = registry.dup
      other.promote('Tilt::RegistryAppOneAlpha', 'fake')

      stub_require(registry, proc do |file|
        assert_equal 'fake_beta', file
        Tilt.const_set(:RegistryAppOneBeta, FakeBeta)
        true
      end)

      stub_require(other, proc do |file|
        assert_equal 'fake_alpha', file
        Tilt.const_set(:RegistryAppOneAlpha, FakeAlpha)
        true
      end)

      assert_equal FakeBeta, registry['page.fake']
      assert_equal FakeAlpha, other['page.fake']
      loaded_snapshot = registry.dup
      assert_nil loaded_snapshot.template_map['fake']
    end
  end

  it 'registers an internal engine without changing the global registry' do
    internal = Class.new
    registry = Tilt.registry
    registry.register(internal, 'app-local')

    assert_equal internal, registry['page.app-local']
    refute Tilt.registered?('app-local')
  end

  it 'reorders lazy candidates with candidate_order' do
    mapping = build_registry
    original = mapping.candidates('fake').map(&:first)

    ordered = mapping.candidate_order('fake', *original.reverse).map(&:first)

    assert_equal original.reverse, ordered
    assert_equal original.reverse, mapping.candidates('fake').map(&:first)
  end

  it 'promotes a candidate without loading it' do
    mapping = build_registry
    mapping.promote('Tilt::RegistryFakeAlpha', 'fake')

    assert_equal [
      ['Tilt::RegistryFakeAlpha', 'fake_alpha'],
      ['Tilt::RegistryFakeBeta', 'fake_beta'],
    ], mapping.candidates('fake').map(&:to_a)
  end

  it 'uses prefer to promote an existing lazy candidate' do
    mapping = build_registry
    mapping.prefer('Tilt::RegistryFakeAlpha', 'fake')

    assert_equal 'Tilt::RegistryFakeAlpha', mapping.candidate_order('fake').first.class_name
  end

  it 'disables one lazy candidate and falls back to the rest' do
    without_fake_constants do
      mapping = build_registry
      mapping.disable_candidate('Tilt::RegistryFakeBeta', 'fake')

      stub_require(mapping, proc do |file|
        assert_equal 'fake_alpha', file
        Tilt.const_set(:RegistryFakeAlpha, FakeAlpha)
        true
      end)

      assert_equal FakeAlpha, mapping['page.fake']
    end
  end

  it 'removes a resolved engine when its candidate is disabled' do
    without_fake_constants do
      mapping = build_registry

      stub_require(mapping, proc do |file|
        Tilt.const_set(:RegistryFakeBeta, FakeBeta) if file == 'fake_beta'
        true
      end)
      assert_equal FakeBeta, mapping['page.fake']

      mapping.disable_candidate('Tilt::RegistryFakeBeta', 'fake')

      stub_require(mapping, proc do |file|
        Tilt.const_set(:RegistryFakeAlpha, FakeAlpha) if file == 'fake_alpha'
        true
      end)
      assert_equal FakeAlpha, mapping['page.fake']
    end
  end

  it 'falls back on LoadError by default' do
    without_fake_constants do
      mapping = build_registry
      required = []

      stub_require(mapping, proc do |file|
        required << file
        next Tilt.const_set(:RegistryFakeAlpha, FakeAlpha) if file == 'fake_alpha'
        raise LoadError, file
      end)

      assert_equal FakeAlpha, mapping['page.fake']
      assert_equal ['fake_beta', 'fake_alpha'], required
    end
  end

  it 'does not fall back when fallback is disabled' do
    mapping = Tilt::Mapping.new(:fallback => false)
    mapping.register_lazy('Tilt::RegistryFakeAlpha', 'fake_alpha', 'strict')
    mapping.register_lazy('Tilt::RegistryFakeBeta', 'fake_beta', 'strict')
    required = []

    stub_require(mapping, proc do |file|
      required << file
      raise LoadError, file
    end)

    error = assert_raises(LoadError) { mapping['page.strict'] }
    assert_equal 'fake_beta', error.message
    assert_equal ['fake_beta'], required
  end

  it 'uses a custom fallback policy' do
    without_fake_constants do
      failed = []
      mapping = Tilt::Mapping.new do |error, candidate_name, candidate_file|
        failed << [candidate_name, candidate_file, error.class]
        error.is_a?(NameError) || error.is_a?(LoadError)
      end
      mapping.register_lazy('Tilt::RegistryFakeAlpha', 'fake_alpha', 'custom')
      mapping.register_lazy('Tilt::RegistryFakeBeta', 'fake_beta', 'custom')

      stub_require(mapping, proc do |file|
        if file == 'fake_alpha'
          Tilt.const_set(:RegistryFakeAlpha, FakeAlpha)
          true
        else
          true
        end
      end)

      assert_equal FakeAlpha, mapping['page.custom']
      assert_equal [['Tilt::RegistryFakeBeta', 'fake_beta', NameError]], failed
    end
  end

  it 'does not leave a resolved registration after a failed load' do
    mapping = build_registry

    stub_require(mapping, proc do |file|
      raise LoadError, file
    end)

    assert_raises(LoadError) { mapping['page.fake'] }
    assert_nil mapping.template_map['fake']
    assert_equal 2, mapping.candidates('fake').length
  end

  it 'creates templates through the registry' do
    template_class = Class.new do
      attr_reader :file
      def initialize(file, *)
        @file = file
      end
    end
    registry = Tilt.registry
    registry.register(template_class, 'appfake')

    template = registry.new('index.appfake')

    assert_instance_of template_class, template
    assert_equal 'index.appfake', template.file
  end

  it 'accepts configuration through a block and copies explicit registrations' do
    internal = Class.new
    registry = Tilt.registry do |configured|
      configured.register(internal, 'blocklocal')
    end

    assert_equal internal, registry['index.blocklocal']
    assert_equal internal, registry.dup['index.blocklocal']
    refute Tilt.registered?('blocklocal')
  end

  it 'does not treat a globally resolved engine as externally preloaded' do
    without_fake_constants do
      Tilt.register_lazy('Tilt::RegistryFakeAlpha', 'fake_alpha', 'snapshot-fake')
      Tilt.register_lazy('Tilt::RegistryFakeBeta', 'fake_beta', 'snapshot-fake')

      global = Tilt.default_mapping
      global.define_singleton_method(:require) do |file|
        Tilt.const_set(:RegistryFakeBeta, FakeBeta) if file == 'fake_beta'
        true
      end
      assert_equal FakeBeta, Tilt['page.snapshot-fake']

      registry = Tilt.registry
      registry.promote('Tilt::RegistryFakeAlpha', 'snapshot-fake')
      registry.define_singleton_method(:require) do |file|
        Tilt.const_set(:RegistryFakeAlpha, FakeAlpha) if file == 'fake_alpha'
        true
      end

      assert_equal FakeAlpha, registry['page.snapshot-fake']
    end
  ensure
    Tilt.unregister('snapshot-fake')
  end

  it 'does not share first-load preference across concurrent mappings' do
    without_fake_constants do
      first = build_named_registry_on('Tilt::RegistryAppTwoAlpha', 'Tilt::RegistryAppTwoBeta', 'fake', Tilt.registry)
      second = first.dup
      second.promote('Tilt::RegistryAppTwoAlpha', 'fake')
      mutex = Mutex.new
      loaded = []
      first_started = Queue.new
      release_first = Queue.new
      errors = []

      stub_require(first, proc do |file|
        if file == 'fake_beta'
          first_started << true
          release_first.pop
        end
        mutex.synchronize { loaded << [:first, file] }
        Tilt.const_set(:RegistryAppTwoBeta, FakeBeta) if file == 'fake_beta'
        true
      end)

      stub_require(second, proc do |file|
        mutex.synchronize { loaded << [:second, file] }
        Tilt.const_set(:RegistryAppTwoAlpha, FakeAlpha) if file == 'fake_alpha'
        true
      end)

      first_thread = Thread.new do
        begin
          first['page.fake']
        rescue => error
          errors << error
        end
      end

      first_started.pop

      second_result = second['page.fake']

      release_first << true
      first_thread.join(2)

      assert_empty errors
      assert_equal FakeAlpha, second_result
      assert_equal FakeBeta, first['page.fake']
      assert_equal [:second, 'fake_alpha'], loaded.entries[0]
      assert_includes loaded, [:first, 'fake_beta']
    end
  end
end
