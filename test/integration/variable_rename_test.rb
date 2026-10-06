# frozen_string_literal: true

require 'test_helper'

class VariableRenameIntegrationTest < Minitest::Test
  include Liquid

  def test_rename_preserves_render_with_renamed_assigns
    source = "{{ title }}\n{% for item in cart.items %}\n\t{{ item.name }} ({{ forloop.index }}) {{ title }}\n{% endfor %}\n{% raw %}{{ title }}{% endraw %}\n"

    assigns = {
      "title" => "Store",
      "cart" => { "items" => [{ "name" => "a" }, { "name" => "b" }] },
    }
    renamed_assigns = {
      "heading" => "Store",
      "cart" => { "items" => [{ "name" => "a" }, { "name" => "b" }] },
    }

    expected = Template.parse(source.dup).render!(assigns)

    migrated = Template.parse(source.dup)
    migrated.rename_variable("title", "heading")
    item_offset = source.index("item", source.index("for"))
    migrated.rename_variable("item", "product", at_byte: item_offset)

    assert_equal(expected, migrated.render!(renamed_assigns))
    assert_includes(migrated.source, "{{ heading }}")
    assert_includes(migrated.source, "{{ product.name }}")
    assert_includes(migrated.source, "forloop.index")
    assert_includes(migrated.source, "{% raw %}{{ title }}{% endraw %}")
    assert_includes(migrated.source, "\t{{ product.name }}")
  end

  def test_shadowed_rename_is_locally_scoped_and_renders_equivalently
    source = "{% for x in xs %}{{ x }}{% for x in ys %}{{ x }}{% endfor %}{% endfor %}"
    assigns = { "xs" => [1, 2], "ys" => [9] }

    inner_loop_start = source.index("for x in ys")
    inner_start = source.index("{{ x }}", inner_loop_start) + 3
    migrated = Template.parse(source.dup)
    migrated.rename_variable("x", "z", at_byte: inner_start)

    assert_equal(Template.parse(source).render!(assigns), migrated.render!(assigns))
    assert_equal("{% for x in xs %}{{ x }}{% for z in ys %}{{ z }}{% endfor %}{% endfor %}", migrated.source)
  end

  def test_dynamic_bracket_access_follows_bindings
    source = %q({{ items[index] }} {{ hash["index"] }} {{ data[index].name }})
    migrated = Template.parse(source.dup)
    migrated.rename_variable("index", "position")

    assigns = {
      "items" => %w[a b],
      "position" => 1,
      "hash" => { "index" => "dynamic" },
      "data" => [],
    }
    assert_equal("b dynamic ", migrated.render!(assigns))
    assert_includes(migrated.source, "items[position]")
    assert_includes(migrated.source, %q(hash["index"]))
    assert_includes(migrated.source, "data[position].name")
  end
end
