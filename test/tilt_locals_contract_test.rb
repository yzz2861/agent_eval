require_relative 'test_helper'
require 'tilt/erubi'
require 'tilt/plain'

# An interpreted template implementation (overrides #evaluate instead of
# compiling to a method), used to test contracts on interpreted adapters.
class LocalsContractInterpretedTemplate < Tilt::Template
  def prepare
  end

  def evaluate(scope, locals, &block)
    locals.map { |key, value| "#{key}=#{value}" }.join(' ')
  end
end

describe "tilt locals contract" do
  def erubi_template(contract, source, file=nil, line=1)
    Tilt::ErubiTemplate.new(file, line, :locals_contract=>contract) { source }
  end

  it "renders when all declared locals are provided" do
    template = erubi_template({:required=>[:name], :optional=>{:title=>'untitled'}}, '<%= [name, title].join(":") %>')
    assert_equal 'alice:ceo', template.render(nil, :name=>'alice', :title=>'ceo')
  end

  it "applies default values for omitted optional locals" do
    template = erubi_template({:required=>[:name], :optional=>{:title=>'untitled'}}, '<%= [name, title].join(":") %>')
    assert_equal 'alice:untitled', template.render(nil, :name=>'alice')
  end

  it "matches locals given with string keys against the contract" do
    template = erubi_template({:required=>[:name], :optional=>{:title=>'untitled'}}, '<%= [name, title].join(":") %>')
    assert_equal 'alice:untitled', template.render(nil, 'name'=>'alice')
  end

  it "raises with template location when a required local is missing" do
    template = erubi_template({:required=>[:name]}, '<%= name %>', 'views/show.erb', 5)
    error = assert_raises(Tilt::LocalsContractError) { template.render(nil, :title=>'x') }
    assert_includes error.message, 'views/show.erb:5'
    assert_includes error.message, ':name'
  end

  it "raises with template location for undeclared locals by default" do
    template = erubi_template({:required=>[:name]}, '<%= name %>', 'views/show.erb', 5)
    error = assert_raises(Tilt::LocalsContractError) { template.render(nil, :name=>'a', :extra=>1) }
    assert_includes error.message, 'views/show.erb:5'
    assert_includes error.message, ':extra'
  end

  it "allows undeclared locals when the contract allows extra locals" do
    template = erubi_template({:required=>[:name], :allow_extra=>true}, '<%= name %>/<%= extra %>')
    assert_equal 'a/1', template.render(nil, :name=>'a', :extra=>1)
  end

  it "raises LocalsContractError, a subclass of ArgumentError" do
    assert_kind_of ArgumentError, Tilt::LocalsContractError.new('x')
  end

  it "rejects invalid contracts at initialization" do
    assert_raises(ArgumentError) { erubi_template('nope', 'x') }
    assert_raises(ArgumentError) { erubi_template({:required=>[:a], :optional=>{:a=>1}}, 'x') }
    assert_raises(ArgumentError) { erubi_template({:required=>[Object.new]}, 'x') }
    assert_raises(ArgumentError) { erubi_template({:required=>[:a, :a]}, 'x') }
  end

  it "renders templates without a contract as before" do
    template = Tilt::ErubiTemplate.new(nil) { '<%= a %>' }
    assert_equal '1', template.render(nil, :a=>'1', :extra=>'x')
    assert_nil template.locals_contract
  end

  it "exposes the normalized contract via #locals_contract" do
    template = erubi_template({:required=>['name'], :optional=>{:title=>'t'}, :allow_extra=>true}, 'x')
    contract = template.locals_contract
    assert_equal [:name], contract.required
    assert_equal({:title=>'t'}, contract.optional)
    assert_equal true, contract.allow_extra?
  end

  it "supports class-level contracts, inheritance, and per-instance overrides" do
    klass = Class.new(Tilt::ErubiTemplate)
    klass.locals_contract = {:required=>[:name]}

    template = klass.new(nil) { '<%= name %>' }
    assert_raises(Tilt::LocalsContractError) { template.render }
    assert_equal 'alice', template.render(nil, :name=>'alice')

    subclass = Class.new(klass)
    assert_raises(Tilt::LocalsContractError) { subclass.new(nil) { 'x' }.render }

    overridden = klass.new(nil, :locals_contract=>{:required=>[:other]}) { '<%= other %>' }
    assert_equal 'o', overridden.render(nil, :other=>'o')

    disabled = klass.new(nil, :locals_contract=>false) { 'body' }
    assert_equal 'body', disabled.render(nil, :anything=>1)
  end

  it "compiles a single method regardless of locals order or subset" do
    template = erubi_template({:required=>[:a, :b], :optional=>{:c=>'C'}}, '<%= a %>|<%= b %>|<%= c %>')
    expectations = {
      {:a=>'1', :b=>'2'} => '1|2|C',
      {:b=>'2', :a=>'1'} => '1|2|C',
      {:a=>'1', :b=>'2', :c=>'3'} => '1|2|3',
      {:c=>'3', :b=>'2', :a=>'1'} => '1|2|3',
      {'a'=>'1', 'b'=>'2'} => '1|2|C',
    }
    expectations.each do |locals, expected|
      assert_equal expected, template.render(nil, locals)
    end
    assert_equal 1, template.instance_variable_get(:@compiled_method).size
  end

  it "compiles a method per locals subset without a contract" do
    template = Tilt::ErubiTemplate.new(nil) { '<%= a %>' }
    template.render(nil, :a=>'1')
    template.render(nil, :a=>'1', :b=>'2')
    assert_equal 2, template.instance_variable_get(:@compiled_method).size
  end

  it "does not share mutable default values across renders" do
    template = erubi_template({:optional=>{:tags=>[]}}, '<%= (tags << "x").join(",") %>')
    assert_equal 'x', template.render
    assert_equal 'x', template.render
  end

  it "calls callable defaults on every render" do
    calls = 0
    default = lambda { calls += 1; [] }
    template = erubi_template({:optional=>{:tags=>default}}, '<%= (tags << "x").join(",") %>')
    assert_equal 'x', template.render
    assert_equal 'x', template.render
    assert_equal 2, calls
  end

  it "duplicates frozen defaults so templates can mutate them" do
    template = erubi_template({:optional=>{:name=>'alice'.freeze}}, '<%= name << "!" %>')
    assert_equal 'alice!', template.render
    assert_equal 'alice!', template.render
  end

  it "does not evaluate the template body when a default value fails" do
    default = lambda { raise 'boom' }
    log = []
    template = erubi_template({:optional=>{:bad=>default}, :allow_extra=>true}, '<% log << :ran %>', 'broken.erb', 9)
    error = assert_raises(Tilt::LocalsContractError) { template.render(nil, :log=>log) }
    assert_empty log
    assert_includes error.message, 'broken.erb:9'
    assert_includes error.message, ':bad'
    assert_equal 'boom', error.cause.message
  end

  it "enforces contracts on interpreted templates" do
    template = Tilt::PlainTemplate.new('notes.txt', 2, :locals_contract=>{:required=>[:name]}) { 'plain body' }
    error = assert_raises(Tilt::LocalsContractError) { template.render }
    assert_includes error.message, 'notes.txt:2'
    assert_equal 'plain body', template.render(nil, :name=>'alice')
  end

  it "provides canonical locals with defaults to interpreted templates" do
    template = LocalsContractInterpretedTemplate.new(nil, :locals_contract=>{:required=>[:a], :optional=>{:b=>'B'}}) { 'ignored' }
    assert_equal 'a=1 b=B', template.render(nil, :a=>1)
  end

  it "rejects undeclared locals on interpreted templates" do
    template = LocalsContractInterpretedTemplate.new(nil, :locals_contract=>{:required=>[:a]}) { 'ignored' }
    assert_raises(Tilt::LocalsContractError) { template.render(nil, :a=>1, :b=>2) }
  end

  it "keeps a single compiled method under concurrent contracted renders" do
    cache = Tilt::Cache.new
    factory = lambda do
      cache.fetch('shared.erb') do
        erubi_template({:required=>[:name], :optional=>{:tags=>[]}}, '<%= name %>:<%= (tags << "x").join(",") %>', 'shared.erb')
      end
    end
    template = factory.call

    results = Queue.new
    errors = Queue.new
    threads = 8.times.map do |i|
      Thread.new do
        25.times do |j|
          locals = j.even? ? {:name=>"n#{i}"} : {:tags=>['y'], :name=>"n#{i}"}
          locals = locals.to_a.rotate(j % locals.size).to_h
          results << factory.call.render(nil, locals)
        rescue => e
          errors << e
        end
      end
    end
    threads.each(&:join)

    unless errors.empty?
      list = []
      list << errors.pop until errors.empty?
      flunk "unexpected errors during concurrent render: #{list.map(&:message).inspect}"
    end

    outputs = []
    outputs << results.pop until results.empty?
    assert_equal 200, outputs.size
    outputs.each do |output|
      assert_match(/\An\d+:(?:x|y,x)\z/, output)
    end
    assert_equal 1, template.instance_variable_get(:@compiled_method).size
  end

  it "enforces contracts under concurrent renders of interpreted templates" do
    template = Tilt::PlainTemplate.new('plain.txt', 4, :locals_contract=>{:required=>[:name]}) { 'plain body' }
    rendered = Queue.new
    rejected = Queue.new
    threads = 8.times.map do |i|
      Thread.new do
        25.times do |j|
          if j.even?
            rendered << template.render(nil, :name=>"n#{i}")
          else
            begin
              template.render
              rendered << :not_rejected
            rescue Tilt::LocalsContractError => e
              rejected << e.message
            end
          end
        end
      end
    end
    threads.each(&:join)

    104.times { assert_equal 'plain body', rendered.pop }
    assert rendered.empty?
    96.times { assert_includes rejected.pop, 'plain.txt:4' }
    assert rejected.empty?
  end
end
