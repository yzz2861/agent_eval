# frozen_string_literal: true

require 'test_helper'

class BytecodeTest < Minitest::Test
  include Liquid

  def test_compile_returns_frozen_reusable_program
    template = Template.parse('{{ x }}')
    program = template.compile_bytecode
    assert_instance_of(Bytecode::Program, program)
    assert(program.iseq.frozen?)
    assert_same(program, template.bytecode_program)
  end

  def test_program_executes_against_context_and_output
    template = Template.parse('{{ x }}!')
    program = template.compile_bytecode
    context = Context.new({ 'x' => 'hi' })
    output = +''
    Bytecode.execute(program, context, output)
    assert_equal('hi!', output)
  end

  def test_unsupported_custom_tag_is_rejected_at_compile_time
    custom_tag = Class.new(Tag) do
      def render_to_output_buffer(_context, output)
        output << 'custom'
        output
      end
    end

    with_custom_tag('experimentallyunsupported', custom_tag) do
      # Ordinary interpreted rendering continues to work.
      template = Template.parse('{% experimentallyunsupported %}')
      assert_equal('custom', template.render!)

      error = assert_raises(Bytecode::UnsupportedSyntaxError) do
        template.compile_bytecode
      end
      assert_match(/experimentallyunsupported/, error.message)

      parse_error = assert_raises(Bytecode::UnsupportedSyntaxError) do
        Template.parse('{% experimentallyunsupported %}', bytecode: true)
      end
      assert_match(/experimentallyunsupported/, parse_error.message)
    end
  end

  def test_unsupported_builtin_tag_is_rejected_but_interpreter_works
    template = Template.parse('{% capture y %}hi{% endcapture %}{{ y }}')
    assert_equal('hi', template.render!)
    assert_raises(Bytecode::UnsupportedSyntaxError) { template.compile_bytecode }
  end

  def test_render_bytecode_option_does_not_affect_normal_render
    with_custom_tag('needsinterp', Class.new(Tag) do
      def render_to_output_buffer(_context, output)
        output << 'ok'
        output
      end
    end) do
      template = Template.parse('{% needsinterp %}')
      assert_equal('ok', template.render!)
      assert_raises(Bytecode::UnsupportedSyntaxError) { template.render!({}, bytecode: true) }
      assert_equal('ok', template.render!)
    end
  end

  def test_parse_with_bytecode_renders_through_vm_by_default
    template = Template.parse('{{ x | upcase }}', bytecode: true)
    assert_instance_of(Bytecode::Program, template.bytecode_program)
    assert_equal('HI', template.render!({ 'x' => 'hi' }))
    assert_equal('HI', template.render({ 'x' => 'hi' }))
  end

  def test_disassembly_lists_instructions_and_nested_bodies
    template = Template.parse('{% unless x %}a{% endunless %}{% for y in zs %}b{% endfor %}')
    listing = template.disassemble_bytecode
    assert_includes(listing, '== document (2 nodes) ==')
    assert_includes(listing, 'test_leaf')
    assert_includes(listing, 'jump_if_false')
    assert_includes(listing, 'for:body')
  end

  def test_no_eval_or_source_generation
    files = Dir[File.expand_path('../../../../lib/liquid/bytecode/**/*.rb', __dir__)]
    files.each do |file|
      source = File.read(file)
      refute_match(/\beval\b/, source, "#{file} must not use eval")
      refute_match(/class_eval|instance_eval|module_eval/, source, "#{file} must not generate code")
    end
  end

  def test_bytecode_module_level_api
    template = Template.parse('{% for x in items %}{{ x }}{% endfor %}')
    program = Bytecode.compile(template)
    output = Bytecode.execute(program, Context.new({ 'items' => [1, 2] }), +'')
    assert_equal('12', output)
    assert_includes(Bytecode.disassemble(program), 'for')
  end
end
