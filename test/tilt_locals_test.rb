require_relative 'test_helper'
require 'tilt/erb'

describe "Tilt locals contracts" do
  # A minimal interpreted template: #evaluate receives the already validated
  # and default-filled locals hash from Template#render.
  _Interpreted = Class.new(Tilt::Template) do
    def prepare
    end

    def evaluate(scope, locals, &block)
      locals.inspect
    end
  end

  def compiled_methods(template)
    template.instance_variable_get(:@compiled_method).size
  end

  it "is nil for templates that do not declare a contract" do
    template = Tilt::ERBTemplate.new { 'Hello' }
    assert_nil template.locals_contract
  end

  it "renders declared required locals (compiled adapter)" do
    template = Tilt::ERBTemplate.new(nil, 1, :locals => [:name]) { 'Hello <%= name %>!' }
    assert_equal "Hello Joe!", template.render(Object.new, :name => 'Joe')
  end

  it "accepts string or symbol keys for the same declared local" do
    template = Tilt::ERBTemplate.new(nil, 1, :locals => [:name]) { 'Hi <%= name %>' }
    assert_equal "Hi Joe", template.render(Object.new, 'name' => 'Joe')
    assert_equal "Hi Joe", template.render(Object.new, :name => 'Joe')
  end

  it "raises for a missing required local with the template location" do
    template = Tilt::ERBTemplate.new('views/greeting.erb', 7, :locals => [:name]) { 'x' }
    error = assert_raises(Tilt::LocalsError) { template.render }
    assert_includes error.message, "views/greeting.erb:7"
    assert_includes error.message, "missing required locals [:name]"
  end

  it "uses the default eval location when there is no file" do
    template = Tilt::ERBTemplate.new(nil, 1, :locals => [:name]) { 'x' }
    error = assert_raises(Tilt::LocalsError) { template.render }
    assert_includes error.message, "(__TEMPLATE__):1"
  end

  it "raises for an unknown local when extras are not allowed" do
    template = Tilt::ERBTemplate.new(nil, 1, :locals => [:name]) { 'x' }
    error = assert_raises(Tilt::LocalsError) do
      template.render(Object.new, :name => 'Joe', :nope => 1)
    end
    assert_includes error.message, "unexpected locals [:nope]"
  end

  it "allows extra locals when configured" do
    options = { :locals => { :name => nil, :allow_extra => true } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { 'Hello <%= name %>' }
    assert_equal "Hello Joe", template.render(Object.new, :name => 'Joe', :other => 9)
  end

  it "fills in a static default for an omitted optional local" do
    options = { :locals => { :greeting => 'hi', :name => nil } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<%= greeting %> <%= name %>' }
    assert_equal "hi Joe", template.render(Object.new, :name => 'Joe')
    assert_equal "yo Bo", template.render(Object.new, :name => 'Bo', :greeting => 'yo')
  end

  it "treats a nil hash value as a required local (terse form)" do
    template = Tilt::ERBTemplate.new(nil, 1, :locals => { :name => nil }) { '<%= name %>' }
    assert_raises(Tilt::LocalsError) { template.render }
    assert_equal "Joe", template.render(Object.new, :name => 'Joe')
  end

  it "accepts the structured required/defaults/allow_extra form" do
    declaration = {
      :required => [:name],
      :defaults => { :greeting => 'hi' },
      :allow_extra => true
    }
    template = Tilt::ERBTemplate.new(nil, 1, :locals => declaration) { '<%= greeting %> <%= name %>' }
    assert_equal "hi Joe", template.render(Object.new, :name => 'Joe')
    assert_equal true, template.locals_contract.allow_extra?
  end

  it "treats an explicitly supplied false as present" do
    options = { :locals => { :enabled => true } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<%= enabled.inspect %>' }
    assert_equal "false", template.render(Object.new, :enabled => false)
    assert_equal "true", template.render
  end

  it "does not share a mutable array default across renders" do
    options = { :locals => { :items => %w[a b] } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { "<%= (items << 'z').object_id %>" }
    first = template.render
    second = template.render
    refute_equal first, second
  end

  it "does not share a mutable hash default across renders" do
    options = { :locals => { :opts => { :page => 1 } } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<% opts[:page] += 1 %><%= opts[:page] %>' }
    assert_equal "2", template.render
    assert_equal "2", template.render
  end

  it "uses Tilt::Default to evaluate a fresh object every render" do
    options = { :locals => { :items => Tilt::Default.new { [] } } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<%= items.object_id %>|<%= (items << 1).size %>' }
    first = template.render
    second = template.render
    refute_equal first.split('|').first, second.split('|').first
    assert_equal "1", first.split('|').last
    assert_equal "1", second.split('|').last
  end

  it "accepts a plain Proc as a default factory" do
    options = { :locals => { :items => proc { [] } } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<%= (items << 1).size %>' }
    assert_equal "1", template.render
    assert_equal "1", template.render
  end

  it "does not execute the template body when a default fails" do
    options = { :locals => { :items => Tilt::Default.new { raise "boom" } } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<% raise "body ran" %>' }
    error = assert_raises(RuntimeError) { template.render }
    assert_equal "boom", error.message
  end

  it "compiles a single method no matter the local order" do
    options = { :locals => [:a, { :b => 2, :c => 3 }] }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<%= a %>,<%= b %>,<%= c %>' }
    assert_equal "1,2,3", template.render(Object.new, :a => 1)
    assert_equal "1,5,3", template.render(Object.new, :c => 3, :b => 5, :a => 1)
    assert_equal "1,2,9", template.render(Object.new, :c => 9, :a => 1)
    assert_equal 1, compiled_methods(template)
  end

  it "still compiles per key set when no contract is declared" do
    template = Tilt::ERBTemplate.new { '<%= a %>' }
    template.render(Object.new, :a => 1, :b => 2)
    template.render(Object.new, :b => 2, :a => 1)
    template.render(Object.new, :a => 1)
    assert_equal 2, compiled_methods(template)
  end

  it "validates concurrently and keeps a single compiled method" do
    options = { :locals => [:a, { :b => 2, :c => 3 }] }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<%= a %>,<%= b %>,<%= c %>' }
    threads = 8.times.map do |i|
      Thread.new do
        200.times do
          order = [[:a, 1], [:b, 2], [:c, 3]].rotate(i)
          assert_equal "1,2,3", template.render(Object.new, order.to_h)
        end
      end
    end
    threads.each(&:join)
    assert_equal 1, compiled_methods(template)
  end

  it "isolates mutable defaults across concurrent renders" do
    options = { :locals => { :items => Tilt::Default.new { [] } } }
    template = Tilt::ERBTemplate.new(nil, 1, options) { '<% items << 1 %><%= items.size %>' }
    results = []
    mutex = Mutex.new
    threads = 8.times.map do
      Thread.new do
        100.times { mutex.synchronize { results << template.render } }
      end
    end
    threads.each(&:join)
    assert_equal 800, results.size
    assert(results.all? { |value| value == "1" })
  end

  it "materializes defaults for an interpreted adapter" do
    template = _Interpreted.new(nil, 1, :locals => [:name, :greeting => 'hi']) { '' }
    materialized = nil
    template.define_singleton_method(:evaluate) { |scope, locals, &block| materialized = locals; '' }
    template.render(Object.new, 'name' => 'Joe')
    assert_equal 'Joe', materialized[:name]
    assert_equal 'hi', materialized[:greeting]
  end

  it "validates locals before the interpreted adapter runs" do
    template = _Interpreted.new(nil, 1, :locals => [:name]) { '' }
    error = assert_raises(Tilt::LocalsError) { template.render }
    assert_includes error.message, "missing required locals [:name]"
  end

  it "attributes the error to the template that declared the contract when nested" do
    inner = Tilt::ERBTemplate.new('inner.erb', 3, :locals => [:name]) { 'x' }
    scope = Object.new
    scope.define_singleton_method(:inner_template) { inner }
    outer = Tilt::ERBTemplate.new('outer.erb', 1, :locals => [:title]) do
      '<%= inner_template.render(Object.new, {}) %>'
    end
    error = assert_raises(Tilt::LocalsError) do
      outer.render(scope, :title => 't')
    end
    assert_includes error.message, "inner.erb:3"
    refute_includes error.message, "outer.erb"
  end

  it "supports a class-level declaration" do
    klass = Class.new(Tilt::ERBTemplate) do
      locals :name
    end
    template = klass.new { 'Hi <%= name %>' }
    refute_nil template.locals_contract
    assert_equal "Hi Joe", template.render(Object.new, :name => 'Joe')
    assert_raises(Tilt::LocalsError) { template.render }
  end

  it "lets an instance option override the class declaration" do
    klass = Class.new(Tilt::ERBTemplate) do
      locals :name
    end
    template = klass.new(nil, 1, :locals => [:other]) { 'x' }
    error = assert_raises(Tilt::LocalsError) { template.render(Object.new, :other => 1, :name => 'Joe') }
    assert_includes error.message, "unexpected locals [:name]"
    assert_raises(Tilt::LocalsError) { template.render(Object.new, :name => 'Joe') }
  end

  it "inherits the class declaration" do
    parent = Class.new(Tilt::ERBTemplate) { locals :name }
    child = Class.new(parent)
    template = child.new { 'Hi <%= name %>' }
    refute_nil template.locals_contract
    assert_equal "Hi Joe", template.render(Object.new, :name => 'Joe')
  end

  it "does not leak the :locals option to the underlying engine" do
    klass = Class.new(Tilt::Template) do
      def prepare
        raise "leaked" if options.key?(:locals)
      end

      def precompiled_template(local_keys)
        "'x'"
      end
    end
    template = klass.new(nil, 1, :locals => [:name]) { 'x' }
    assert_equal "x", template.render(Object.new, :name => 'Joe')
  end

  it "rejects an invalid declared name" do
    assert_raises(ArgumentError) do
      Tilt::ERBTemplate.new(nil, 1, :locals => ['BAD']) { 'x' }
    end
  end
end

describe "Tilt locals contracts with real adapters" do
  it "works with the compiled ERBTemplate adapter" do
    require 'tilt/erb'
    template = Tilt::ERBTemplate.new(nil, 1, :locals => [:title, :items => Tilt::Default.new { [] }]) do
      "<%= title %>:<%= items.size %>"
    end
    assert_equal "Home:0", template.render(Object.new, :title => 'Home')
    assert_equal 1, template.instance_variable_get(:@compiled_method).size
  end

  it "works with the interpreted RadiusTemplate adapter" do
    require 'tilt/radius'
    template = Tilt::RadiusTemplate.new(nil, 1, :locals => [:name, :greeting => 'hey']) do
      "<r:greeting /> <r:name />"
    end
    assert_equal "hey Joe", template.render(nil, :name => 'Joe')
  rescue LoadError
    skip "radius not installed"
  end

  it "works with the interpreted LiquidTemplate adapter" do
    require 'tilt/liquid'
    template = Tilt::LiquidTemplate.new(nil, 1, :locals => [:name, :greeting => 'hey']) do
      "{{ greeting }} {{ name }}"
    end
    assert_equal "hey Joe", template.render(nil, :name => 'Joe')
  rescue LoadError
    skip "liquid not installed"
  end
end
