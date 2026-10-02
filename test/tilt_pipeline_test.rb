require_relative 'test_helper'

describe 'tilt/pipeline' do
  before do
    @mapping = Tilt.default_mapping.dup
    @pipeline_class = @mapping.register_pipeline('str.erb')
  end

  it "returns a template class" do
    assert_equal Tilt::Pipeline, @pipeline_class.superclass
  end

  it "registers itself for the given extension" do
    assert_equal @pipeline_class, @mapping['test.str.erb']
  end

  it "renders templates starting with final extension to inner extensions" do
    template = @pipeline_class.new { |t| '#<%= \'{a = 1}\' %><%= \'#{a}\' %>' }
    assert_equal "11", template.render
  end

  it "can be rendered more than once" do
    template = @pipeline_class.new { |t| '<%= \'#{1}\' %>' }
    3.times { assert_equal "1", template.render }
  end

  it "passing locals" do
    template = @pipeline_class.new { |t| '<%= \'#{a}\' * a %>' }
    assert_equal "333", template.render(Object.new, :a => 3)
  end

  it "evaluating in an object scope" do
    template = @pipeline_class.new { |t| '<%= \'#{a}\' * a %>' }
    o = Object.new
    def o.a; 3 end
    assert_equal "333", template.render(o)
  end

  it "passing a block for yield" do
    template = @pipeline_class.new { |t| '<%= \'#{yield}\' * yield %>' }
    assert_equal "333", template.render { 3 }
    assert_equal "22", template.render { 2 }
  end
end

describe 'tilt/pipeline (options)' do
  before do
    @mapping = Tilt.default_mapping.dup
  end

  it "supports :templates option for specifying templates to use in order" do
    pipeline = @mapping.register_pipeline('setrrb', :templates=>['erb', 'str'])
    template = pipeline.new { |t| '#<%= \'{a = 1}\' %><%= \'#{a}\' %>' }
    assert_equal "11", template.render
  end

  it "supports :extra_exts option for specifying additional extensions to register" do
    @mapping.register_pipeline('str.erb', :extra_exts=>['setrrb', 'asdfoa'])
    ['str.erb', 'setrrb', 'asdfoa'].each do |ext|
      template = @mapping[ext].new { |t| '#<%= \'{a = 1}\' %><%= \'#{a}\' %>' }
      assert_equal "11", template.render
    end
  end

  it "supports per template class options" do
    pipeline = @mapping.register_pipeline('str.erb', 'erb'=>{:outvar=>'@foo'})
    template = pipeline.new { |t| '#<% @foo << \'{a = 1}\' %><%= \'#{a}\' %>' }
    assert_equal "11", template.render
  end
end

describe 'tilt/pipeline (stage diagnostics)' do
  # Fake adapter that doubles every line and provides a line mapping
  # from output lines back to input lines.
  class DoublingTemplate < Tilt::Template
    def prepare
    end

    def evaluate(scope, locals, &block)
      mapping = {}
      output = []
      data.each_line.with_index(1) do |line, index|
        2.times do
          output << line
          mapping[output.size] = index
        end
      end
      Tilt::Pipeline::StageOutput.new(output.join, mapping)
    end
  end

  # Fake adapter that prefixes every line and only returns a String,
  # so it has no line mapping.
  class PrefixingTemplate < Tilt::Template
    def prepare
    end

    def evaluate(scope, locals, &block)
      data.each_line.map { |line| "> #{line}" }.join
    end
  end

  # Fake adapter that fails while transforming the input.
  class ExplodingTemplate < Tilt::Template
    def prepare
    end

    def evaluate(scope, locals, &block)
      raise 'transform failed' if data.include?('EXPLODE')
      data
    end
  end

  before do
    @mapping = Tilt.default_mapping.dup
    @mapping.register(DoublingTemplate, 'dbl')
    @mapping.register(PrefixingTemplate, 'prefix')
    @mapping.register(ExplodingTemplate, 'explode')
  end

  it "renders the unwrapped text of stages returning a StageOutput" do
    pipeline = @mapping.register_pipeline('x', :templates=>['dbl', 'erb'])
    template = pipeline.new { |t| "a\n<%= 1 + 1 %>\n" }
    assert_equal "a\na\n2\n2\n", template.render
  end

  it "renders a String when the final stage returns a StageOutput" do
    pipeline = @mapping.register_pipeline('x', :templates=>['dbl'])
    template = pipeline.new { |t| "x\ny\n" }
    assert_equal "x\nx\ny\ny\n", template.render
  end

  it "maps the error line of a later stage back through a stage with a line mapping" do
    pipeline = @mapping.register_pipeline('x', :templates=>['dbl', 'erb'])
    template = pipeline.new { |t| "ok\n<% raise 'boom' %>\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    assert_equal 'erb', error.stage_name
    assert_equal 2, error.stage_index
    assert_equal 3, error.output_line
    assert_equal 2, error.input_line
    assert_instance_of RuntimeError, error.cause
    assert_equal 'boom', error.cause.message
    assert_includes error.message, 'erb'
    assert_includes error.message, 'line 2 of the template source'
    refute_includes error.message, 'boom'
    refute_includes error.message, '<% raise'
  end

  it "marks positions as intermediate text when a stage has no line mapping" do
    pipeline = @mapping.register_pipeline('x', :templates=>['prefix', 'erb'])
    template = pipeline.new { |t| "ok\n<% raise 'boom' %>\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    assert_equal 'erb', error.stage_name
    assert_equal 2, error.output_line
    assert_nil error.input_line
    assert_includes error.message, 'intermediate text'
  end

  it "does not map through an unmapped stage even if an earlier stage has a mapping" do
    pipeline = @mapping.register_pipeline('x', :templates=>['dbl', 'prefix', 'erb'])
    template = pipeline.new { |t| "ok\n<% raise 'boom' %>\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    assert_equal 3, error.output_line
    assert_nil error.input_line
    assert_includes error.message, 'intermediate text'
  end

  it "reports the stage when a stage fails while transforming the input" do
    pipeline = @mapping.register_pipeline('x', :templates=>['explode', 'erb'])
    template = pipeline.new { |t| "EXPLODE\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    assert_equal 'explode', error.stage_name
    assert_equal 1, error.stage_index
    assert_nil error.output_line
    assert_nil error.input_line
    assert_instance_of RuntimeError, error.cause
    assert_equal 'transform failed', error.cause.message
  end

  it "reports syntax errors raised while compiling the final stage" do
    pipeline = @mapping.register_pipeline('x', :templates=>['erb'])
    template = pipeline.new { |t| "a\n<% if true %>\nb\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    assert_equal 'erb', error.stage_name
    assert_kind_of Integer, error.output_line
    assert_equal error.output_line, error.input_line
    assert_instance_of SyntaxError, error.cause
  end

  it "reports the failing stage path and translated line for nested pipelines" do
    @mapping.register_pipeline('innererb', :templates=>['erb'])
    outer = @mapping.register_pipeline('x', :templates=>['dbl', 'innererb'])
    template = outer.new { |t| "ok\n<% raise 'boom' %>\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    assert_equal 'innererb>erb', error.stage_name
    assert_equal 3, error.output_line
    assert_equal 2, error.input_line
    assert_instance_of Tilt::Pipeline::StageError, error.cause
    assert_equal 'erb', error.cause.stage_name
    assert_instance_of RuntimeError, error.cause.cause
    assert_equal 'boom', error.cause.cause.message
  end

  it "does not include template content in the error message" do
    pipeline = @mapping.register_pipeline('x', :templates=>['dbl', 'erb'])
    template = pipeline.new { |t| "SECRET_TEMPLATE_CONTENT\n<% raise 'boom' %>\n" }
    error = assert_raises(Tilt::Pipeline::StageError) { template.render }
    refute_includes error.message, 'SECRET_TEMPLATE_CONTENT'
  end
end
