require 'helper'
require 'rexml/document'

class TestSlimXMLNamespaces < TestSlim
  XML_OPTIONS = {format: :xml, xml_namespaces: true}

  class XMLScope
    def item_attrs
      {
        'xmlns:a' => 'urn:a',
        'xmlns:b' => 'urn:b',
        'a:id' => 'one',
        'b:id' => 'two'
      }
    end

    def dynamic_item
      {
        'tag' => 'b:item',
        'xmlns' => 'urn:a',
        'xmlns:b' => 'urn:b',
        'b:label' => 'dynamic',
        'b:a-label' => 'local'
      }
    end

    def unbound_attrs
      {'undeclared:name' => 'invalid'}
    end

    def dynamic_tag_attrs
      {'tag' => 'b:item', 'id' => 'dynamic-tag'}
    end

    def rebinding_uri
      'urn:rebound'
    end

    def dynamic_attributes
      [['undeclared:name', 'invalid']]
    end
  end

  def test_static_default_namespace_rebinding_and_attributes
    source = <<~SLIM
      root xmlns="urn:root" xmlns:a="urn:a" xmlns:b="urn:b"
        a:item id="a-id"
          child xmlns="urn:child" xmlns:a="urn:a-child"
            a:nested xmlns:b="urn:b-child" b:id="b-parent" b:new-id="b-child" /
    SLIM

    output = render(source, XML_OPTIONS)
    document = REXML::Document.new(output)
    root = document.root
    item = root.elements[1]
    child = item.elements[1]
    nested = child.elements[1]

    assert_equal 'urn:root', root.namespace
    assert_equal 'root', root.local_name
    assert_equal 'urn:a', item.namespace
    assert_equal 'item', item.local_name
    assert_equal '', item.attribute('id').namespace
    assert_equal 'urn:child', child.namespace
    assert_equal 'urn:a-child', nested.namespace
    assert_equal 'nested', nested.local_name
    assert_equal 'urn:b-child', nested.attribute('id', 'urn:b-child').namespace
    assert_equal 'urn:b-child', nested.attribute('new-id', 'urn:b-child').namespace
  end

  def test_same_attribute_expanded_name_from_different_prefixes_is_rejected
    source = <<~SLIM
      root xmlns="urn:root" xmlns:a="urn:same" xmlns:b="urn:same"
        item a:id="one" b:id="two" /
    SLIM

    assert_raises Slim::DuplicateAttributeError do
      render(source, XML_OPTIONS)
    end
  end

  def test_current_element_declaration_binds_its_static_attributes
    source = <<~'SLIM'
      root xmlns="urn:root"
        item xmlns:new="urn:new" new:label="value" /
SLIM

    document = REXML::Document.new(render(source, XML_OPTIONS))

    assert_equal 'urn:new', document.root.elements[1].attribute('label', 'urn:new').namespace
  end

  def test_dynamic_splat_resolves_declarations_and_current_scope
    source = <<~SLIM
      root xmlns="urn:root" xmlns:b="urn:outer-b"
        item *item_attrs
          b:child /
    SLIM

    document = REXML::Document.new(render(source, XML_OPTIONS.merge(scope: XMLScope.new)))
    item = document.root.elements[1]

    assert_equal 'urn:root', item.namespace
    assert_equal 'one', item.attribute('id', 'urn:a').value
    assert_equal 'two', item.attribute('id', 'urn:b').value
    assert_equal 'urn:b', item.elements[1].namespace
  end

  def test_dynamic_splat_rebinds_for_current_tag_and_children
    source = <<~SLIM
      root xmlns="urn:root" xmlns:b="urn:outer-b"
        wrapper
          *dynamic_item
            b:child /
          b:after /
    SLIM

    document = REXML::Document.new(render(source, XML_OPTIONS.merge(scope: XMLScope.new)))
    wrapper = document.root.elements[1]
    item = wrapper.elements[1]

    assert_equal 'urn:b', item.namespace
    assert_equal 'item', item.local_name
    assert_equal 'dynamic', item.attribute('label', 'urn:b').value
    assert_equal 'local', item.attribute('a-label', 'urn:b').value
    assert_equal 'urn:b', item.elements[1].namespace
    assert_equal 'urn:outer-b', wrapper.elements[2].namespace
  end

  def test_dynamic_tag_name_uses_current_namespace_scope
    source = <<~SLIM
      root xmlns="urn:root" xmlns:b="urn:b"
        *dynamic_tag_attrs /
    SLIM

    document = REXML::Document.new(render(source, XML_OPTIONS.merge(scope: XMLScope.new)))
    tag = document.root.elements[1]

    assert_equal 'urn:b', tag.namespace
    assert_equal 'item', tag.local_name
    assert_equal '', tag.attribute('id').namespace
  end

  def test_unbound_static_prefix_is_a_compile_error
    source = <<~'SLIM'
      root xmlns="urn:root"
        undeclared:item /
SLIM

    error = assert_raises Slim::Parser::SyntaxError do
      render(source, XML_OPTIONS)
    end

    assert_equal 'Unbound XML namespace prefix \'undeclared\'', error.error
  end

  def test_unbound_default_namespace_is_a_compile_error
    error = assert_raises Slim::Parser::SyntaxError do
      render("root\n", XML_OPTIONS)
    end

    assert_equal 'Unbound default XML namespace', error.error
  end

  def test_empty_default_namespace_declaration_rebinds_to_no_namespace
    source = <<~'SLIM'
      root xmlns="urn:root"
        child xmlns="" /
SLIM

    document = REXML::Document.new(render(source, XML_OPTIONS))

    assert_equal 'urn:root', document.root.namespace
    assert_equal '', document.root.elements[1].namespace
  end

  def test_dynamic_namespace_binding_applies_to_current_and_children
    source = <<~'SLIM'
      root xmlns="urn:root"
        x:item xmlns:x=rebinding_uri
          x:child /
SLIM

    document = REXML::Document.new(render(source, XML_OPTIONS.merge(scope: XMLScope.new)))
    item = document.root.elements[1]

    assert_equal 'urn:rebound', item.namespace
    assert_equal 'urn:rebound', item.elements[1].namespace
  end

  def test_unbound_dynamic_prefix_is_rejected_before_current_tag
    source = <<~'SLIM'
      root xmlns="urn:root"
        item *unbound_attrs /
SLIM

    error = assert_raises Slim::InvalidNamespacePrefixError do
      render(source, XML_OPTIONS.merge(scope: XMLScope.new))
    end

    assert_equal 'Unbound XML namespace prefix \'undeclared\'', error.message
  end

  def test_unbound_dynamic_code_attribute_is_rejected
    source = <<~'SLIM'
      root xmlns="urn:root"
        item *dynamic_attributes /
SLIM

    error = assert_raises Slim::InvalidNamespacePrefixError do
      render(source, XML_OPTIONS.merge(scope: XMLScope.new))
    end

    assert_equal 'Unbound XML namespace prefix \'undeclared\'', error.message
  end

  def test_default_html_mode_keeps_colon_names_literal
    source = <<~SLIM
      html:body
        html:p html:id="test" Text
    SLIM

    assert_html '<html:body><html:p html:id="test">Text</html:p></html:body>', source
  end
end
