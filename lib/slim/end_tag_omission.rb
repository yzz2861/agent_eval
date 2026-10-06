# frozen_string_literal: true
module Slim
  # Optional compile time optimization which omits end tags that are
  # optional according to the HTML specification. Example:
  #
  #   ul
  #     li one
  #     li two
  #
  # compiles to `<ul><li>one<li>two</ul>` instead of
  # `<ul><li>one</li><li>two</li></ul>`.
  #
  # The optimization works on the Temple expression tree at compile
  # time (not on the rendered output) and is only applied if the
  # option `omit_end_tags` is set and the output format is `:html`.
  # An end tag is only omitted if the compiler can prove that the
  # HTML parser will produce the same DOM tree:
  #
  # - The following sibling must be a static HTML start tag which is
  #   allowed to follow the element directly (e.g. `li` after `li`),
  #   or the element must be the last statically known content of a
  #   static parent element ("no more content in the parent element").
  # - Anything that is not statically known keeps the end tag:
  #   dynamic output, control flow (if/loops), text, whitespace,
  #   comments and raw HTML interpolation are all treated as barriers.
  # - Nothing is omitted in XML/XHTML mode, in pretty printing mode
  #   (which injects whitespace between tags) or inside foreign
  #   content (SVG/MathML).
  #
  # @api private
  class EndTagOmission < Filter
    # Elements which switch the HTML parser into foreign content.
    # Optional end tag rules do not apply inside SVG/MathML.
    FOREIGN_CONTENT = %w[svg math].freeze

    # Elements with an optional end tag, mapped to the start tags which
    # may directly follow the element if its end tag is omitted.
    # See https://html.spec.whatwg.org/multipage/syntax.html#optional-tags
    FOLLOWERS = {
      'li'       => %w[li],
      'dt'       => %w[dt dd],
      'dd'       => %w[dd dt],
      'p'        => %w[address article aside blockquote details div dl fieldset
                       figcaption figure footer form h1 h2 h3 h4 h5 h6 header
                       hgroup hr main menu nav ol p pre section table ul],
      'rt'       => %w[rt rp],
      'rp'       => %w[rt rp],
      'optgroup' => %w[optgroup],
      'option'   => %w[option optgroup],
      'thead'    => %w[tbody tfoot],
      'tbody'    => %w[tbody tfoot],
      'tfoot'    => %w[],
      'tr'       => %w[tr],
      'td'       => %w[td th],
      'th'       => %w[td th]
    }.freeze

    # Elements whose end tag may also be omitted if there is no more
    # content in the parent element. `thead` is missing intentionally,
    # its end tag may only be omitted before tbody/tfoot.
    EOF_ALLOWED = %w[li dt dd p rt rp optgroup option tbody tfoot tr td th].freeze

    # A `p` end tag may only be omitted at the end of the parent if the
    # parent is not one of these elements (and not a custom element).
    P_EOF_FORBIDDEN_PARENTS = %w[a audio del ins map noscript video].freeze

    define_options :omit_end_tags, :format, :pretty

    def initialize(opts = {})
      super
      # Pretty printing inserts whitespace between tags. With an omitted
      # end tag the HTML parser would assign this whitespace to a
      # different node, so the optimization is only safe for compact
      # HTML output.
      @omit = options[:omit_end_tags] && options[:format] == :html && !options[:pretty]
    end

    def call(exp)
      return exp unless @omit
      @foreign = false
      compile(exp)
    end

    def on_html_tag(name, attrs, content = nil)
      foreign = @foreign
      @foreign = true if FOREIGN_CONTENT.include?(name.to_s.downcase)
      result = [:html, :tag, name, compile(attrs)]
      if content
        content = compile(content)
        # The content of a static HTML tag is statically known to be
        # followed by the parent's end tag, so the "no more content in
        # the parent element" rule may be applied to its last element.
        omit_last_end_tag(content, name.to_s.downcase) if !@foreign && content[0] == :multi
        result << content
      end
      result
    ensure
      @foreign = foreign
    end

    def on_multi(*exps)
      exps = exps.map {|exp| compile(exp) }
      unless @foreign
        exps.each_with_index do |exp, i|
          next unless (name = omissible_tag(exp))
          follower = following_tag(exps, i)
          exps[i] = omit_end_tag(exp) if follower && FOLLOWERS[name].include?(follower)
        end
      end
      [:multi, *exps]
    end

    private

    # Apply the "no more content in the parent element" rule to the
    # last element of a static tag's content sequence.
    def omit_last_end_tag(content, parent)
      i = content.size - 1
      i -= 1 while i > 0 && transparent?(content[i])
      return if i <= 0 || !(name = omissible_tag(content[i])) || !EOF_ALLOWED.include?(name)
      return if name == 'p' && (P_EOF_FORBIDDEN_PARENTS.include?(parent) || parent.include?('-'))
      content[i] = omit_end_tag(content[i])
    end

    # Return the tag name of the next statically known sibling start
    # tag, skipping expressions which produce no output. Anything else
    # (text, whitespace, comments, dynamic output, control flow, ...)
    # is a barrier and returns nil.
    def following_tag(exps, i)
      i += 1
      while i < exps.size
        exp = exps[i]
        return tag_name(exp) unless transparent?(exp)
        i += 1
      end
      nil
    end

    # Expressions which compile to no output at all. `[:newline]` is
    # only used for pretty printing (which disables this optimization).
    def transparent?(exp)
      exp == [:newline] || (exp[0] == :static && exp[1].empty?)
    end

    # Name of the element if it is a static HTML tag with an optional
    # end tag, nil otherwise.
    def omissible_tag(exp)
      name = tag_name(exp)
      name if name && FOLLOWERS.key?(name)
    end

    # Downcased name of a static HTML tag expression, nil otherwise.
    def tag_name(exp)
      return unless Array === exp && exp[0] == :html && exp[1] == :tag
      name = exp[2]
      name.to_s.downcase if String === name || Symbol === name
    end

    # Replace `[:html, :tag, name, attrs, content]` by an expression
    # which only renders the start tag and the content. The downstream
    # Temple HTML filters render a contentless tag in :html format
    # without an end tag (the same way void elements are rendered).
    def omit_end_tag(exp)
      if exp.length > 4
        [:multi, [:html, :tag, exp[2], exp[3]], exp[4]]
      else
        exp
      end
    end
  end
end
