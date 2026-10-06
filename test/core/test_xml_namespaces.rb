require 'helper'
require 'rexml/document'

class TestSlimXMLNamespaces < TestSlim
  def test_default_namespace
    source = <<~SLIM
      root xmlns="urn:root"
        child id="x"
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)

    assert_equal 'urn:root', document.root.namespace
    assert_equal 'root', document.root.local_name
    assert_equal 'urn:root', document.elements['root/child'].namespace
    assert_equal 'child', document.elements['root/child'].local_name
    assert_equal '', document.elements['root/child/@id'].namespace
    assert_equal 'id', document.elements['root/child/@id'].local_name
  end

  def test_prefixed_namespaces_and_local_rebinding
    source = <<~SLIM
      root(xmlns:a="urn:a" xmlns:b="urn:b")
        a:item a:id="one"
        b:section(xmlns:b="urn:c" xmlns:c="urn:d")
          b:title c:label="hello"
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)

    item = document.elements['root/a:item']
    section = document.elements['root/b:section']
    title = document.elements['root/b:section/b:title']

    assert_equal 'urn:a', item.namespace
    assert_equal 'item', item.local_name
    assert_equal 'urn:a', item.attributes.get_attribute('a:id').namespace
    assert_equal 'urn:c', section.namespace
    assert_equal 'urn:c', title.namespace
    assert_equal 'title', title.local_name
    assert_equal 'urn:d', title.attributes.get_attribute('c:label').namespace
    assert_equal 'label', title.attributes.get_attribute('c:label').local_name
  end

  def test_splat_tag_and_attributes_use_current_scope
    source = <<~'SLIM'
      root(xmlns:a="urn:a" xmlns:b="urn:b")
        *{tag: 'a:item', 'a:id' => 'one', 'b:name' => 'two'}
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)
    item = document.elements['root/a:item']

    assert_equal 'urn:a', item.namespace
    assert_equal 'item', item.local_name
    assert_equal 'urn:a', item.attributes.get_attribute('a:id').namespace
    assert_equal 'urn:b', item.attributes.get_attribute('b:name').namespace
  end

  def test_dynamic_unprefixed_tag_has_no_namespace
    source = <<~'SLIM'
      root xmlns:a="urn:a"
        *{tag: 'item', 'id' => 'one'}
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)
    item = document.elements['root/item']

    assert_equal '', item.namespace
    assert_equal '', item.attributes.get_attribute('id').namespace
  end

  def test_splat_can_rebind_namespace_for_descendants
    source = <<~'SLIM'
      root xmlns:a="urn:a"
        wrapper *{"xmlns:a" => "urn:c"}
          *{tag: 'a:item'}
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)

    assert_equal 'urn:c', document.elements['root/wrapper/a:item'].namespace
  end

  def test_splat_can_define_namespace_for_current_tag
    source = <<~'SLIM'
      root xmlns:a="urn:a"
        item *{"xmlns:b" => "urn:b", "b:id" => "dynamic"}
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)

    assert_equal 'urn:b', document.elements['root/item/@b:id'].namespace
  end

  def test_dynamic_default_namespace_rebinding
    source = <<~'SLIM'
      - uri = "urn:dynamic"
      root xmlns="urn:root"
        child xmlns=(uri)
          leaf
    SLIM

    xml = render(source, xml_namespaces: true, format: :xml)
    document = REXML::Document.new(xml)

    assert_equal 'urn:root', document.root.namespace
    assert_equal 'urn:dynamic', document.elements['root/child'].namespace
    assert_equal 'urn:dynamic', document.elements['root/child/leaf'].namespace
  end

  def test_static_same_expanded_name_is_rejected
    source = <<~SLIM
      root(xmlns:a="urn:x" xmlns:b="urn:x" a:id="a" b:id="b")
    SLIM

    error = assert_raises(Slim::Parser::SyntaxError) do
      render(source, xml_namespaces: true, format: :xml)
    end
    assert_match(/Multiple .*id attributes specified/, error.message)
  end

  def test_dynamic_same_expanded_name_is_rejected
    source = <<~'SLIM'
      root(xmlns:a="urn:x" xmlns:b="urn:x")
        item *{"a:id" => "a", "b:id" => "b"}
    SLIM

    error = assert_raises(Slim::XMLNamespaceError) do
      render(source, xml_namespaces: true, format: :xml)
    end
    assert_match(/Multiple .*id attributes specified/, error.message)
  end

  def test_static_unbound_prefix_fails_at_compile_time
    source = <<~SLIM
      root
        a:item
    SLIM

    assert_raises(Slim::Parser::SyntaxError) do
      render(source, xml_namespaces: true, format: :xml)
    end
  end

  def test_static_empty_prefixed_namespace_fails_at_compile_time
    source = <<~SLIM
      root(xmlns:a="")
    SLIM

    assert_raises(Slim::Parser::SyntaxError) do
      render(source, xml_namespaces: true, format: :xml)
    end
  end

  def test_dynamic_unbound_prefix_fails_before_tag_output
    source = <<~'SLIM'
      root xmlns:a="urn:a"
        item *{"a:id" => "a", "b:missing" => true}
    SLIM

    assert_raises(Slim::XMLNamespaceError) do
      render(source, xml_namespaces: true, format: :xml)
    end
  end

  def test_html_mode_keeps_colon_names_as_lexical_names
    source = <<~SLIM
      html:body
        html:p html:id="test" Text
    SLIM

    assert_html '<html:body><html:p html:id="test">Text</html:p></html:body>', source
  end
end
