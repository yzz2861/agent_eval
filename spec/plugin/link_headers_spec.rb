require_relative "../spec_helper"

describe "link_headers plugin" do
  def link_app(&block)
    app(:bare) do
      plugin :link_headers

      route do |r|
        instance_exec(&block)
      end
    end
  end

  def link_header(&block)
    link_app(&block)
    req[1][RodaResponseHeaders::LINK]
  end

  it "builds pagination links with relative URIs, multiple rels, and encoded parameters" do
    header = link_header do
      response.link "items?page=2&q=a,b", rel: :next
      response.link "items?page=1&q=a,b", rel: :prev
      response.link "items?page=5&q=a,b", rel: [:last, :page]
      response.link "items/1/metadata", rel: :describedby, type: "application/ld+json"
      response.link "items?page=5&q=a,b", rel: [:last, :page],
        title: 'Chapter "Five", Part 1',
        "title*" => "UTF-8''chapter-five"
    end

    header.must_equal [
      '<items?page=2&q=a,b>; rel="next"',
      '<items?page=1&q=a,b>; rel="prev"',
      '<items?page=5&q=a,b>; rel="last page"',
      '<items/1/metadata>; rel="describedby"; type="application/ld+json"',
      '<items?page=5&q=a,b>; rel="last page"; title="Chapter \\"Five\\", Part 1"; title*=UTF-8\'\'chapter-five'
    ].join(", ")
  end

  it "merges only links with the same URI, relations, and parameters" do
    header = link_header do
      response.headers[RodaResponseHeaders::LINK] = [
      '</x>; rel="next"; title=X',
      '</x>; rel="prev"; crossorigin',
      '</other>; rel="next"'
    ].join(", ")

      response.link "/x", rel: :NEXT, title: "X"
      response.link "/x", rel: :next, anchor: "#top"
    end

    header.must_equal [
      '</x>; rel="next"; title=X',
      '</x>; rel="prev"; crossorigin',
      '</other>; rel="next"',
      '</x>; rel="next"; anchor=#top'
    ].join(", ")
  end

  it "preserves legal parameters that are not interpreted by the interface" do
    header = link_header do
      response.headers[RodaResponseHeaders::LINK] = '</style.css>; rel=preload; as=style; custom=value; noparam'
      response.link "/app.js", rel: :preload, as: :script
    end

    header.must_equal '</style.css>; rel="preload"; as=style; custom=value; noparam, </app.js>; rel="preload"; as=script'
  end

  it "preserves links without relations and relative fragment URIs" do
    header = link_header do
      response.headers[RodaResponseHeaders::LINK] = '</#section>, </a>; rel=next'
      response.delete_link rel: :next
    end

    header.must_equal '</#section>'
  end

  it "deletes by relation while keeping the same URI with other relations" do
    header = link_header do
      response.headers[RodaResponseHeaders::LINK] = '</a>; rel="next last", </a>; rel="prev", </b>; rel="next"'
      response.delete_link "/a", rel: :next
      response.delete_link rel: :prev
    end

    header.must_equal '</a>; rel="last", </b>; rel="next"'
  end

  it "supports a URI filter with a positional options hash" do
    header = link_header do
      response.headers[RodaResponseHeaders::LINK] = '</a>; rel="next prev", </b>; rel="next"'
      response.delete_link "/a", {rel: :prev}
    end

    header.must_equal '</a>; rel="next", </b>; rel="next"'
  end

  it "removes the Link header when all structured links are deleted" do
    link_app do
      response.link "/a", rel: :next
      response.delete_link
      "ok"
    end

    req[1].wont_include RodaResponseHeaders::LINK
  end

  it "supports extension relations and headers supplied as arrays" do
    header = link_header do
      response.headers[RodaResponseHeaders::LINK] = ['</a>; rel="http://example.com/rel"']
      response.link "/a", rel: "http://example.com/rel"
      response.link "/a", rel: :next
    end

    header.must_equal '</a>; rel="http://example.com/rel", </a>; rel="next"'
  end

  it "fails before returning when an existing Link header contains an illegal newline" do
    link_app do
      response.headers[RodaResponseHeaders::LINK] = "</a>; rel=next\r\nX-Injected: 1"
      "ok"
    end

    proc{req}.must_raise Roda::RodaError
  end

  it "fails when adding a relation containing an illegal newline" do
    link_app do
      response.link "/a", rel: "next\r\nX-Injected: 1"
      "ok"
    end

    proc{req}.must_raise Roda::RodaError
  end

  it "fails when adding an invalid extended parameter value" do
    link_app do
      response.link "/a", rel: :next, "x*" => "bad value"
      "ok"
    end

    proc{req}.must_raise Roda::RodaError
  end
end
