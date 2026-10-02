require_relative "../spec_helper"

describe "early_hints plugin" do 
  def eh_link(*links)
    links = links.join("\n") if Rack.release < '3'
    {RodaResponseHeaders::LINK=>links}
  end

  it "allows sending early hints to rack.early_hints" do
    queue = []
    app(:early_hints) do |r|
      send_early_hints('link'=>'</foo.js>; rel=preload; as=script')
      queue << 'OK'
      'OK'
    end

    body.must_equal 'OK'
    queue.must_equal ['OK']

    queue = []
    body('rack.early_hints'=>proc{|h| queue << h}).must_equal 'OK'
    queue.must_equal [{'link'=>'</foo.js>; rel=preload; as=script'}, 'OK']
  end

  it "collects link hints and submits them all on commit" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.css', :as => 'style')
      add_early_hint('/b.js', :as => 'script')
      commit_early_hints
      'OK'
    end

    body.must_equal 'OK'
    hints.must_equal []

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</a.css>; rel=preload; as=style',
      '</b.js>; rel=preload; as=script',
    )]
  end

  it "accepts raw link values and arrays of link values" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('</a.css>; rel=preload; as=style')
      add_early_hint(['</b.js>; rel=preload; as=script', '</c.png>; rel=preload; as=image'])
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</a.css>; rel=preload; as=style',
      '</b.js>; rel=preload; as=script',
      '</c.png>; rel=preload; as=image',
    )]
  end

  it "deduplicates hints with the same target and attributes regardless of attribute order or string/symbol keys" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.js', :as => 'script', :crossorigin => 'anonymous')
      add_early_hint('/a.js', 'crossorigin' => 'anonymous', 'as' => 'script')
      add_early_hint('</a.js>; crossorigin=anonymous; as=script')
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</a.js>; rel=preload; as=script; crossorigin=anonymous',
    )]
  end

  it "keeps separate hints for the same target with different attributes" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.js', :as => 'script')
      add_early_hint('/a.js', :as => 'fetch', :crossorigin => nil)
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</a.js>; rel=preload; as=script',
      '</a.js>; rel=preload; as=fetch; crossorigin',
    )]
  end

  it "allows removing all collected hints for a resource" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.js', :as => 'script')
      add_early_hint('/a.js', :as => 'fetch', :crossorigin => nil)
      add_early_hint('/b.css', :as => 'style')
      remove_early_hint('/a.js')
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</b.css>; rel=preload; as=style',
    )]
  end

  it "allows removing only the hint matching the given attributes" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.js', :as => 'script')
      add_early_hint('/a.js', :as => 'fetch', :crossorigin => nil)
      remove_early_hint('/a.js', :as => 'script')
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</a.js>; rel=preload; as=fetch; crossorigin',
    )]
  end

  it "ignores removal of resources or attribute combinations that were not collected" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.js', :as => 'script')
      remove_early_hint('/b.js')
      remove_early_hint('/a.js', :as => 'fetch')
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</a.js>; rel=preload; as=script',
    )]
  end

  it "clears collected hints after commit, allowing hints to be collected and committed again" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.css', :as => 'style')
      commit_early_hints
      add_early_hint('/b.js', :as => 'script')
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [
      eh_link('</a.css>; rel=preload; as=style'),
      eh_link('</b.js>; rel=preload; as=script'),
    ]
  end

  it "does not send an empty commit and is a no-op when no hints are pending" do
    calls = 0
    app(:early_hints) do |r|
      add_early_hint('/a.css', :as => 'style')
      remove_early_hint('/a.css')
      commit_early_hints
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| calls += 1}).must_equal 'OK'
    calls.must_equal 0
  end

  it "still returns the page when rack.early_hints is not present" do
    app(:early_hints) do |r|
      add_early_hint('/a.css', :as => 'style')
      commit_early_hints
      send_early_hints('Link' => '</b.js>; rel=preload; as=script')
      'OK'
    end

    body.must_equal 'OK'
  end

  it "does not let send_early_hints affect collected hints" do
    hints = []
    app(:early_hints) do |r|
      add_early_hint('/a.css', :as => 'style')
      send_early_hints(RodaResponseHeaders::LINK=>'</b.js>; rel=preload; as=script')
      commit_early_hints
      'OK'
    end

    body('rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [
      {RodaResponseHeaders::LINK=>'</b.js>; rel=preload; as=script'},
      eh_link('</a.css>; rel=preload; as=style'),
    ]
  end

  it "supports not committing hints for branches that redirect" do
    hints = []
    app(:early_hints) do |r|
      r.get 'redirect' do
        add_early_hint('/a.css', :as => 'style')
        r.redirect '/target'
      end

      r.get 'page' do
        add_early_hint('/b.js', :as => 'script')
        commit_early_hints
        'OK'
      end
    end

    status('/redirect', 'rack.early_hints'=>proc{|h| hints << h}).must_equal 302
    body('/page', 'rack.early_hints'=>proc{|h| hints << h}).must_equal 'OK'
    hints.must_equal [eh_link(
      '</b.js>; rel=preload; as=script',
    )]
  end
end
