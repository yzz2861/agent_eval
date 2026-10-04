# frozen_string_literal: true

require 'test_helper'

class RenderSourceMapTest < Minitest::Test
  include Liquid

  def test_disabled_by_default
    template = Template.parse('plain {{ value }}')
    output = template.render!('value' => 'text')

    assert_equal('plain text', output)
    assert_nil(template.source_map)
  end

  def test_output_matches_normal_render_without_copying_values
    template = Template.parse('plain {{ secret | upcase }}', source_map: true)
    output = template.render!('secret' => 'sensitive')

    assert_equal('plain SENSITIVE', output)

    entries = template.source_map.entries
    assert_equal([0...6, 6...15], entries.map(&:output_byte_range))
    assert_equal([0...6, 6...27], entries.map(&:template_byte_range))
    assert_equal(['plain ', 'Liquid::Variable'], entries.map { |entry| entry.node.is_a?(TextNode) ? 'plain ' : entry.node.class.name })
    serialized_entries = entries.map do |entry|
      {
        output_byte_range: entry.output_byte_range.to_a,
        template_name: entry.template_name,
        template_byte_range: entry.template_byte_range.to_a,
        render_stack: entry.render_stack.map(&:to_h),
      }
    end
    refute_includes(Marshal.dump(serialized_entries), 'SENSITIVE')
    refute_includes(Marshal.dump(serialized_entries), 'sensitive')
  end

  def test_records_plain_text_and_actual_filtered_output_byte_ranges
    template = Template.parse('é{{ value | slice: 0, 1 }}', source_map: true)
    output = template.render!('value' => 'abc')

    assert_equal('éa', output)
    text_entry, variable_entry = template.source_map.entries
    assert_equal(0...2, text_entry.output_byte_range)
    assert_equal(0...2, text_entry.template_byte_range)
    assert_equal(2...3, variable_entry.output_byte_range)
    assert_equal(2...27, variable_entry.template_byte_range)
  end

  def test_ranges_are_relative_to_rendered_output_with_prefilled_buffer
    template = Template.parse('{{ value }}', source_map: true)
    output = +'prefix'
    result = template.render!(
      Liquid::Context.build(outer_scope: { 'value' => 'text' }),
      output: output,
    )

    assert_same(output, result)
    assert_equal('prefixtext', result)
    assert_equal([0...4], template.source_map.entries.map(&:output_byte_range))
  end

  def test_records_each_loop_invocation_separately
    template = Template.parse('{% for item in items %}x{{ item }}{% endfor %}', source_map: true)
    output = template.render!('items' => %w[a bb])

    assert_equal('xaxbb', output)

    item_entries = template.source_map.entries.select { |entry| entry.node.is_a?(Variable) }
    assert_equal([1...2, 3...5], item_entries.map(&:output_byte_range))
    assert_equal([24...34, 24...34], item_entries.map(&:template_byte_range))
    refute_equal(item_entries.first.object_id, item_entries.last.object_id)
  end

  def test_records_render_call_stack_for_partials_and_render_loops
    file_system = StubFileSystem.new(
      'card' => '[{{ item }}]',
    )
    environment = Environment.build(file_system: file_system)
    template = Template.parse(
      '{% render "card" for items as item %}',
      source_map: true,
      environment: environment,
    )
    output = template.render!('items' => %w[a bb])

    assert_equal('[a][bb]', output)

    item_entries = template.source_map.entries.select do |entry|
      entry.node.instance_of?(Liquid::Variable) && entry.template_name == 'card'
    end
    assert_equal([1...2, 4...6], item_entries.map(&:output_byte_range))
    assert_equal([1, 2], item_entries.map { |entry| entry.render_stack.first.iteration })
    assert_equal([1, 1], item_entries.map { |entry| entry.render_stack.length })
    assert_equal(['render', 'render'], item_entries.map { |entry| entry.render_stack.first.tag_name })
    assert_equal(['card', 'card'], item_entries.map { |entry| entry.render_stack.first.template_name })
  end

  def test_records_nested_render_call_stack
    file_system = StubFileSystem.new(
      'outer' => '{% render "inner", value: "deep" %}',
      'inner' => '{{ value }}',
    )
    environment = Environment.build(file_system: file_system)
    template = Template.parse(
      '{% render "outer" %}',
      source_map: true,
      environment: environment,
    )
    output = template.render!

    assert_equal('deep', output)
    inner_entry = template.source_map.entries.find do |entry|
      entry.node.instance_of?(Liquid::Variable) && entry.template_name == 'inner'
    end
    assert_equal(['outer', 'inner'], inner_entry.render_stack.map(&:template_name))
    assert_equal(['render', 'render'], inner_entry.render_stack.map(&:tag_name))
  end

  def test_replaces_source_map_on_each_render
    template = Template.parse('{{ value }}', source_map: true)
    template.render!('value' => 'one')
    first_map = template.source_map
    template.render!('value' => 'longer')
    second_map = template.source_map

    refute_same(first_map, second_map)
    assert_equal([0...3], first_map.entries.map(&:output_byte_range))
    assert_equal([0...6], second_map.entries.map(&:output_byte_range))
  end

  def test_does_not_map_captured_intermediate_output
    template = Template.parse(
      '{% capture saved %}{{ secret }}{% endcapture %}{{ saved }}',
      source_map: true,
    )
    output = template.render!('secret' => 'private')

    assert_equal('private', output)
    assert_equal([0...7], template.source_map.entries.map(&:output_byte_range))
    assert_equal(['Liquid::Variable'], template.source_map.entries.map { |entry| entry.node.class.name })
  end

  def test_records_trimmed_plain_text_against_actual_source
    source = "before \n{{- value -}}\n after"
    template = Template.parse(source, source_map: true)
    output = template.render!('value' => 'x')

    assert_equal('beforexafter', output)

    text_sources = template.source_map.entries.filter_map do |entry|
      next unless entry.node.is_a?(TextNode)

      source.byteslice(entry.template_byte_range)
    end

    assert_equal(['before', 'after'], text_sources)
  end
end
