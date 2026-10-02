require_relative "../spec_helper"

describe "link_headers plugin" do
  it "builds pagination links with relative URIs and encoded parameters" do
    app(:link_headers) do |r|
      link_headers.add 'items?page=3&q="a,b"', rel: :next
      link_headers.add 'items?page=1', rel: :prev
      link_headers.add 'docs', rel: :describedby, title: 'pagination, "docs"', hreflang: ['en', 'fr-CA']
      ''
    end

    header(RodaResponseHeaders::LINK).must_equal(
      '<items?page=3&q=%22a,b%22>; rel="next", ' +
      '<items?page=1>; rel="prev", ' +
      '<docs>; rel="describedby"; title="pagination, \\"docs\\""; hreflang="en"; hreflang="fr-CA"'
    )
  end

  it "supports multiple relations and extension parameters" do
    app(:link_headers) do |r|
      link_headers.add 'alternate', rel: [:next, 'prev'], anchor: '#section', custom: true
      ''
    end

    header(RodaResponseHeaders::LINK).must_equal '<alternate>; rel="next prev"; anchor="#section"; custom'
  end

  it "supports RFC 8187 extended parameter values" do
    app(:link_headers) do |r|
      link_headers.add 'docs', rel: :describedby, 'title*': "UTF-8'en'%C3%A9"
      ''
    end

    header(RodaResponseHeaders::LINK).must_equal "<docs>; rel=\"describedby\"; title*=UTF-8'en'%C3%A9"
  end

  it "merges with existing Link headers and preserves unknown parameters" do
    app(:bare) do
      plugin :link_headers

      route do |r|
        response[RodaResponseHeaders::LINK] =
          '<https://example.com/a?x=1,2>; rel=next; anchor="#old"; data-keep="yes, keep"; x-flag, ' +
          '<https://example.com/a?x=1,2>; rel=prev; anchor="#old", ' +
          '<https://example.com/other>; rel=describedby; title="other"'

        link_headers.add 'https://example.com/a?x=1,2', rel: :next, title: 'next, "updated"'
        ''
      end
    end

    header(RodaResponseHeaders::LINK).must_equal(
      '<https://example.com/a?x=1,2>; rel="next"; anchor="#old"; data-keep="yes, keep"; x-flag; title="next, \\"updated\\"", ' +
      '<https://example.com/a?x=1,2>; rel="prev"; anchor="#old", ' +
      '<https://example.com/other>; rel="describedby"; title="other"'
    )
  end

  it "does not merge links with the same URI but different relation sets" do
    app(:link_headers) do |r|
      link_headers.add 'same', rel: :next, anchor: '#a'
      link_headers.add 'same', rel: :prev, anchor: '#b'
      link_headers.add 'same', rel: 'next prev'
      ''
    end

    header(RodaResponseHeaders::LINK).must_equal(
      '<same>; rel="next"; anchor="#a", ' +
      '<same>; rel="prev"; anchor="#b", ' +
      '<same>; rel="next prev"'
    )
  end

  it "supports existing header values split across an array" do
    app(:bare) do
      plugin :link_headers

      route do |r|
        response[RodaResponseHeaders::LINK] = [
          '<first>; rel=next; x-keep=yes',
          '<second>; rel=prev'
        ]
        link_headers.add 'third', rel: :describedby
        ''
      end
    end

    header(RodaResponseHeaders::LINK).must_equal(
      '<first>; rel="next"; x-keep=yes, <second>; rel="prev", <third>; rel="describedby"'
    )
  end

  it "deletes links by relation, URI, or both" do
    app(:bare) do
      plugin :link_headers

      route do |r|
        link_headers.add '/p1', rel: :prev
        link_headers.add '/p3', rel: :next
        link_headers.add '/same', rel: 'next prev'
        link_headers.add '/same', rel: :prev
        link_headers.add '/docs', rel: :describedby

        r.on 'relation' do
          link_headers.delete rel: :next
        end

        r.on 'uri-and-relation' do
          link_headers.delete '/p1', rel: :prev
        end

        r.on 'uri' do
          link_headers.delete '/docs'
        end

        r.on 'all' do
          link_headers.delete
        end

        ''
      end
    end

    header(RodaResponseHeaders::LINK, '/relation').must_equal(
      '</p1>; rel="prev", </same>; rel="prev", </docs>; rel="describedby"'
    )
    header(RodaResponseHeaders::LINK, '/uri-and-relation').must_equal(
      '</p3>; rel="next", </same>; rel="next prev", </same>; rel="prev", </docs>; rel="describedby"'
    )
    header(RodaResponseHeaders::LINK, '/uri').must_equal(
      '</p1>; rel="prev", </p3>; rel="next", </same>; rel="next prev", </same>; rel="prev"'
    )
    header(RodaResponseHeaders::LINK, '/all').must_be_nil
  end

  it "raises before returning a response for invalid newlines in existing headers" do
    app(:link_headers) do |r|
      response[RodaResponseHeaders::LINK] = "</next>; rel=next, </bad>; rel=\"evil\nInjection\""
      ''
    end

    proc { req }.must_raise Roda::RodaError
  end

  it "raises when adding an invalid URI" do
    app(:link_headers) do |r|
      link_headers.add "/bad\nuri", rel: :next
      ''
    end

    proc { req }.must_raise Roda::RodaError
  end

  it "raises when extension parameters contain header injection" do
    app(:link_headers) do |r|
      link_headers.add '/next', rel: :next, title: "safe\nInjection"
      ''
    end

    proc { req }.must_raise Roda::RodaError
  end

  it "raises when an existing Link header is malformed" do
    @app = _app do
      plugin :link_headers

      route do |r|
        response[RodaResponseHeaders::LINK] = '<missing-end; rel=next'
        link_headers.add '/next', rel: :next
        ''
      end
    end

    proc { req }.must_raise Roda::RodaError
  end

  it "raises when an existing Link value repeats rel" do
    @app = _app do
      plugin :link_headers

      route do |r|
        response[RodaResponseHeaders::LINK] = '<a>; rel=next; rel=prev'
        link_headers.add '/b', rel: :next
        ''
      end
    end

    proc { req }.must_raise Roda::RodaError
  end

  it "raises when existing Link values are not separated by a comma" do
    proc do
      Roda::RodaPlugins::LinkHeaders::Builder.new('<a>; rel=next <b>; rel=prev')
    end.must_raise Roda::RodaError
  end
end
