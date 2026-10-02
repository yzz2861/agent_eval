require_relative 'test_helper'
require 'tilt/string'
require 'tilt/erb'
require 'tilt/pipeline'

describe Tilt::RenderBudget do
  def string_template(file=nil, &block)
    Tilt::StringTemplate.new(file, &block)
  end

  # Two templates that indirectly call each other through yield,
  # recursing until the budget stops them.
  def mutual_render(a, b)
    render_next = nil
    render_next = lambda do |t|
      t.render { render_next.call(t.equal?(a) ? b : a) }
    end
    render_next.call(a)
  end

  it 'requires at least one limit' do
    assert_raises(ArgumentError) { Tilt::RenderBudget.new }
    assert_raises(ArgumentError) { Tilt::RenderBudget.new(:max_depth=>'8') }
    assert_raises(ArgumentError) { Tilt::RenderBudget.new(:max_renders=>-1) }
  end

  it 'has no current budget by default' do
    assert_nil Tilt::RenderBudget.current
    assert_equal 'x', string_template { '#{yield}' }.render { 'x' }
  end

  it 'limits the depth of a render chain' do
    a = string_template('a.str') { '#{yield}' }
    b = string_template('b.str') { '#{yield}' }
    budget = Tilt::RenderBudget.new(:max_depth=>8)

    error = assert_raises(Tilt::RenderBudgetExceeded) do
      budget.with { mutual_render(a, b) }
    end

    assert_equal :depth, error.limit
    assert_same budget, error.budget
    assert_equal %w[a.str b.str a.str b.str], error.chain.first(4)
    assert_equal 0, budget.depth
  end

  it 'limits the cumulative number of renders' do
    t = string_template { 'hi' }
    budget = Tilt::RenderBudget.new(:max_renders=>3)

    budget.with do
      3.times { assert_equal 'hi', t.render }
      error = assert_raises(Tilt::RenderBudgetExceeded) { t.render }
      assert_equal :renders, error.limit
    end

    assert_equal 0, budget.depth
    assert_equal 4, budget.renders
  end

  it 'keeps the exception chain bounded in length' do
    t = string_template('loop.str') { '#{yield}' }
    render_next = nil
    render_next = lambda { t.render { render_next.call } }
    budget = Tilt::RenderBudget.new(:max_depth=>100)

    error = assert_raises(Tilt::RenderBudgetExceeded) do
      budget.with { render_next.call }
    end

    assert_operator error.chain.length, :<=, Tilt::RenderBudgetExceeded::CHAIN_LIMIT + 1
    assert_equal '...', error.chain.last
  end

  it 'returns the depth when a render raises' do
    t = string_template { '#{yield}' }
    budget = Tilt::RenderBudget.new(:max_depth=>8, :max_renders=>8)

    budget.with do
      assert_raises(RuntimeError) { t.render { raise 'boom' } }
      assert_equal 0, budget.depth
      assert_equal 'ok', t.render { 'ok' }
    end
  end

  it 'does not let repeated enter/exit bypass the cumulative count' do
    t = string_template { '#{yield}' }
    budget = Tilt::RenderBudget.new(:max_renders=>2)

    budget.with do
      2.times { assert_raises(RuntimeError) { t.render { raise 'boom' } } }
      assert_equal 0, budget.depth
      assert_equal 2, budget.renders
      assert_raises(Tilt::RenderBudgetExceeded) { t.render { 'x' } }
    end
  end

  it 'restores the previously active budget after with blocks' do
    outer = Tilt::RenderBudget.new(:max_renders=>1)
    inner = Tilt::RenderBudget.new(:max_renders=>1)
    t = string_template { 'x' }

    outer.with do
      inner.with { t.render }
      assert_same outer, Tilt::RenderBudget.current
      assert_equal 0, outer.renders
      t.render
      assert_raises(Tilt::RenderBudgetExceeded) { t.render }
    end

    assert_nil Tilt::RenderBudget.current
  end

  it 'gives each fiber its own current budget' do
    budgets = []
    fibers = 2.times.map do
      Fiber.new do
        budget = Tilt::RenderBudget.new(:max_renders=>2)
        budget.with do
          t = string_template { 'x' }
          2.times { t.render }
          budgets << budget
          Fiber.yield
          assert_raises(Tilt::RenderBudgetExceeded) { t.render }
        end
      end
    end

    fibers.each(&:resume)
    assert_nil Tilt::RenderBudget.current
    fibers.each(&:resume)
    assert_equal [3, 3], budgets.map(&:renders)
  end

  it 'allows callers to explicitly share a budget between fibers' do
    budget = Tilt::RenderBudget.new(:max_renders=>3)
    t = string_template { 'x' }
    fibers = 2.times.map do
      Fiber.new do
        budget.with do
          t.render
          Fiber.yield
          t.render
        end
      end
    end

    fibers.each(&:resume)
    fibers.first.resume
    assert_raises(Tilt::RenderBudgetExceeded) { fibers.last.resume }
    assert_equal 4, budget.renders
  end

  it 'applies across pipeline stages' do
    mapping = Tilt.default_mapping.dup
    pipeline_class = mapping.register_pipeline('str.erb')
    template = pipeline_class.new { '<%= 1 + 1 %>' }

    budget = Tilt::RenderBudget.new(:max_renders=>1)
    assert_raises(Tilt::RenderBudgetExceeded) { budget.with { template.render } }

    budget = Tilt::RenderBudget.new(:max_renders=>3)
    assert_equal '2', budget.with { template.render }
  end

  it 'applies across nested renders combined with pipelines' do
    mapping = Tilt.default_mapping.dup
    pipeline_class = mapping.register_pipeline('str.erb')
    inner = pipeline_class.new('inner.str.erb') { '<%= 1 + 1 %>' }
    outer = string_template('outer.str') { '#{yield}' }

    budget = Tilt::RenderBudget.new(:max_depth=>2)
    assert_raises(Tilt::RenderBudgetExceeded) do
      budget.with { outer.render { inner.render } }
    end

    budget = Tilt::RenderBudget.new(:max_depth=>3)
    assert_equal '2', budget.with { outer.render { inner.render } }
  end
end
