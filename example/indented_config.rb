# An indentation sensitive config format with lists and nested objects.
# The grammar consumes layout events (enter/same/exit) provided by
# Parslet::Layout instead of counting spaces itself.

$:.unshift File.dirname(__FILE__) + "/../lib"

require 'pp'
require 'parslet'


class IndentedConfig < Parslet::Parser
  L = Parslet::Layout.new(comment: '#')

  root(:document)
  rule(:document) do
    (L.start >> node >> (L.same >> node).repeat >> L.finish).as(:doc)
  end

  # A node is a 'key:' pair or a '- value' list item, optionally followed
  # by a nested block one indentation level deeper.
  rule(:node)   { (pair | item) >> nested.maybe }
  rule(:nested) do
    L.scope(
      L.enter >> node >> (L.same >> node).repeat >> L.exit
    ).as(:children)
  end

  rule(:pair) do
    (key.as(:key) >> str(':') >> (str(' ') >> value).maybe).as(:pair)
  end
  rule(:item)   { (str('- ') >> value).as(:item) }
  rule(:key)    { match('[A-Za-z0-9_]').repeat(1) }

  # Bracket expressions may span several lines; layout recognition is
  # suspended while the brackets are open.
  rule(:value) do
    str('[') >> match('[^\]]').repeat.as(:ilist) >> str(']') |
      match('[^\n]').repeat(1).as(:scalar)
  end
end

class IndentedConfigTransform < Parslet::Transform
  # A list of sibling nodes becomes a merged hash when all of them are
  # key/value pairs, and a plain array otherwise (list items).
  ASSEMBLE = lambda do |nodes|
    list = nodes.is_a?(Array) ? nodes : [nodes]
    if list.all? { |node| node.is_a?(Hash) }
      list.reduce({}) { |acc, node| acc.merge(node) }
    else
      list
    end
  end

  SCALAR = lambda do |text|
    text =~ /\A-?\d+\z/ ? text.to_i : text
  end

  VALUE = lambda do |hash|
    if hash[:scalar]
      SCALAR.call(hash[:scalar].to_s.strip)
    elsif hash[:ilist]
      hash[:ilist].to_s.split(',').map { |e| SCALAR.call(e.strip) }
    end
  end

  rule(pair: subtree(:p), children: subtree(:c)) do
    { p[:key].to_s => ASSEMBLE.call(c) }
  end
  rule(pair: subtree(:p))   { { p[:key].to_s => VALUE.call(p) } }
  rule(item: subtree(:v))   { VALUE.call(v) }
  rule(doc: subtree(:nodes)) { ASSEMBLE.call(nodes) }
end

config = <<~CFG
  # Example configuration
  server:
    host: example.com
    ports:
      - 80
      - 443
    options:
      retry: 3
      tags: [alpha,
             beta]

  db:
    host: localhost
    # default port
    port: 5432
CFG

tree = IndentedConfig.new.parse(config)
pp IndentedConfigTransform.new.apply(tree)
