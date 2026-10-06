require 'helper'

class TestSlimEndTagOmission < TestSlim
  # Minimal HTML tree builder which mirrors the "generate implied end
  # tags" behavior of the HTML parser for the elements with optional
  # end tags. It is used to prove that omitting end tags does not
  # change the resulting node containment.
  class DomTree
    VOID_ELEMENTS = %w[area base br col embed hr img input link meta param source track wbr].freeze

    # Start tag => open elements it implicitly closes while they are
    # the current node (simplified HTML tree construction rules)
    IMPLIED_END_TAGS = Hash.new([].freeze).merge(
      'li'       => %w[li],
      'dt'       => %w[dt dd],
      'dd'       => %w[dt dd],
      'rt'       => %w[rt rp],
      'rp'       => %w[rt rp],
      'option'   => %w[option],
      'optgroup' => %w[option optgroup],
      'td'       => %w[td th],
      'th'       => %w[td th],
      'tr'       => %w[td th tr],
      'thead'    => %w[td th tr],
      'tbody'    => %w[td th tr thead],
      'tfoot'    => %w[td th tr thead]
    ).freeze

    # Start tags which implicitly close an open p element
    P_CLOSERS = %w[address article aside blockquote details div dl fieldset
                   figcaption figure footer form h1 h2 h3 h4 h5 h6 header
                   hgroup hr main menu nav ol p pre section table ul].freeze

    Node = Struct.new(:name, :children)

    def self.parse(html)
      root = Node.new('#document', [])
      stack = [root]
      html.scan(/<!--.*?-->|<[^>]+>|[^<]+/m) do |token|
        case token
        when /\A<!--/
          stack.last.children << Node.new('#comment', [token])
        when /\A<[!?]/
          # Doctype / processing instruction, not part of the tree
        when /\A<\//
          name = token[2..-2].strip.downcase
          if stack.any? {|node| node.name == name }
            stack.pop while stack.last.name != name
            stack.pop
          end
        when /\A</
          name = token[1..-2].sub(%r{/\s*\z}, '').split(/\s+/).first.downcase
          stack.pop while IMPLIED_END_TAGS[name].include?(stack.last.name)
          stack.pop if P_CLOSERS.include?(name) && stack.last.name == 'p'
          node = Node.new(name, [])
          stack.last.children << node
          stack.push(node) unless VOID_ELEMENTS.include?(name)
        else
          stack.last.children << Node.new('#text', [token])
        end
      end
      root
    end
  end

  def render_omit(source, options = {})
    render(source, {format: :html, omit_end_tags: true}.merge(options))
  end

  # Assert the exact output before/after enabling the optimization and
  # assert that both outputs parse to the same DOM tree.
  def assert_omit(expected_omitted, expected_full, source, options = {})
    assert_equal expected_omitted, render_omit(source, options)
    assert_equal expected_full, render(source, {format: :html}.merge(options))
    assert_equal DomTree.parse(expected_full), DomTree.parse(expected_omitted),
      'Omitting end tags changed the DOM tree'
  end

  def test_list_items
    source = %q{
ul
  li one
  li two
  li three
}
    assert_omit '<ul><li>one<li>two<li>three</ul>',
                '<ul><li>one</li><li>two</li><li>three</li></ul>', source
  end

  def test_nested_lists
    source = %q{
ul
  li
    ul
      li a
      li b
  li c
}
    assert_omit '<ul><li><ul><li>a<li>b</ul><li>c</ul>',
                '<ul><li><ul><li>a</li><li>b</li></ul></li><li>c</li></ul>', source
  end

  def test_list_item_with_attributes
    source = %q{
ul
  li.first a
  li#second b
}
    assert_omit '<ul><li class="first">a<li id="second">b</ul>',
                '<ul><li class="first">a</li><li id="second">b</li></ul>', source
  end

  def test_empty_list_item
    source = %q{
ul
  li
  li b
}
    assert_omit '<ul><li><li>b</ul>',
                '<ul><li></li><li>b</li></ul>', source
  end

  def test_table
    source = %q{
table
  thead
    tr
      th A
      th B
  tbody
    tr
      td 1
      td 2
    tr
      td 3
      td 4
}
    assert_omit '<table><thead><tr><th>A<th>B<tbody><tr><td>1<td>2<tr><td>3<td>4</table>',
                '<table><thead><tr><th>A</th><th>B</th></tr></thead>' +                '<tbody><tr><td>1</td><td>2</td></tr><tr><td>3</td><td>4</td></tr></tbody></table>',
                source
  end

  def test_thead_without_tbody_keeps_end_tag
    # thead may only be omitted before tbody/tfoot, not at the end
    # of the parent.
    source = %q{
table
  thead
    tr
      th A
}
    assert_omit '<table><thead><tr><th>A</thead></table>',
                '<table><thead><tr><th>A</th></tr></thead></table>', source
  end

  def test_definition_list
    source = %q{
dl
  dt term
  dd definition
  dt term2
  dd definition2
}
    assert_omit '<dl><dt>term<dd>definition<dt>term2<dd>definition2</dl>',
                '<dl><dt>term</dt><dd>definition</dd><dt>term2</dt><dd>definition2</dd></dl>', source
  end

  def test_paragraph_followed_by_block
    source = %q{
div
  p one
  p two
  div three
}
    assert_omit '<div><p>one<p>two<div>three</div></div>',
                '<div><p>one</p><p>two</p><div>three</div></div>', source
  end

  def test_paragraph_at_end_of_parent
    source = %q{
div
  p one
}
    assert_omit '<div><p>one</div>',
                '<div><p>one</p></div>', source
  end

  def test_paragraph_at_end_of_anchor_keeps_end_tag
    # A p end tag may not be omitted at the end of an a element.
    source = %q{
a href="#"
  p one
}
    assert_omit '<a href="#"><p>one</p></a>',
                '<a href="#"><p>one</p></a>', source
  end

  def test_paragraph_followed_by_text_keeps_end_tag
    source = %q{
div
  p one
  | text
}
    assert_omit '<div><p>one</p>text</div>',
                '<div><p>one</p>text</div>', source
  end

  def test_select_options
    source = %q{
select
  option a
  option b
  optgroup label="g"
    option c
}
    assert_omit '<select><option>a<option>b<optgroup label="g"><option>c</select>',
                '<select><option>a</option><option>b</option>' +                '<optgroup label="g"><option>c</option></optgroup></select>', source
  end

  def test_ruby_annotation
    source = %q{
ruby
  | word
  rt reading
  rp note
}
    assert_omit '<ruby>word<rt>reading<rp>note</ruby>',
                '<ruby>word<rt>reading</rt><rp>note</rp></ruby>', source
  end

  def test_comment_is_barrier
    source = %q{
ul
  li one
  /! comment
  li two
}
    assert_omit '<ul><li>one</li><!--comment--><li>two</ul>',
                '<ul><li>one</li><!--comment--><li>two</li></ul>', source
  end

  def test_whitespace_text_is_barrier
    source = %q{
ul
  li one
  '
  li two
}
    assert_omit '<ul><li>one</li> <li>two</ul>',
                '<ul><li>one</li> <li>two</li></ul>', source
  end

  def test_dynamic_output_is_barrier
    source = %q{
ul
  li one
  == hello_world
  li two
}
    assert_omit '<ul><li>one</li>Hello World from @env<li>two</ul>',
                '<ul><li>one</li>Hello World from @env<li>two</li></ul>', source
  end

  def test_control_flow_is_barrier
    source = %q{
ul
  li one
  - if @x > 0
    li two
  li three
}
    assert_omit '<ul><li>one</li><li>three</ul>',
                '<ul><li>one</li><li>three</li></ul>', source
  end

  def test_li_inside_conditional_keeps_end_tag
    # The content after the if block is not statically known, so the
    # li inside the block keeps its end tag.
    source = %q{
ul
  - if @x > 0
    li one
  li two
}
    assert_omit '<ul><li>two</ul>',
                '<ul><li>two</li></ul>', source
  end

  def test_li_inside_loop_keeps_end_tag
    source = %q{
ul
  - 2.times do
    li one
}
    assert_omit '<ul><li>one</li><li>one</li></ul>',
                '<ul><li>one</li><li>one</li></ul>', source
  end

  def test_siblings_inside_conditional
    # Siblings inside the same control flow branch are still optimized.
    source = %q{
ul
  - if @x == 0
    li one
    li two
}
    assert_omit '<ul><li>one<li>two</li></ul>',
                '<ul><li>one</li><li>two</li></ul>', source
  end

  def test_svg_foreign_content
    source = %q{
svg
  li one
  li two
}
    assert_omit '<svg><li>one</li><li>two</li></svg>',
                '<svg><li>one</li><li>two</li></svg>', source
  end

  def test_math_foreign_content
    source = %q{
math
  li one
  li two
}
    assert_omit '<math><li>one</li><li>two</li></math>',
                '<math><li>one</li><li>two</li></math>', source
  end

  def test_root_level_last_tag_keeps_end_tag
    # The template might be rendered inside a layout, so "no more
    # content in the parent" cannot be proven at the root level.
    assert_omit '<li>one<li>two</li>',
                '<li>one</li><li>two</li>', "li one\nli two"
  end

  def test_disabled_by_default
    source = "ul\n  li one\n  li two"
    assert_equal '<ul><li>one</li><li>two</li></ul>', render(source, format: :html)
  end

  def test_disabled_in_xhtml_mode
    source = "ul\n  li one\n  li two"
    assert_equal '<ul><li>one</li><li>two</li></ul>', render(source, omit_end_tags: true)
  end

  def test_disabled_in_xml_mode
    source = "ul\n  li one\n  li two"
    assert_equal '<ul><li>one</li><li>two</li></ul>', render(source, format: :xml, omit_end_tags: true)
  end

  def test_disabled_in_pretty_mode
    source = "ul\n  li one\n  li two"
    assert_equal "<ul>\n  <li>\n    one\n  </li>\n  <li>\n    two\n  </li>\n</ul>",
                 render(source, format: :html, omit_end_tags: true, pretty: true)
  end
end
