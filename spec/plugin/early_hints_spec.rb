require_relative "../spec_helper"

describe "early_hints plugin" do
  LINK = Roda::RodaResponseHeaders::LINK

  def early_hints_app
    app(:early_hints) do |r|
      r.is 'immediate' do
        send_early_hints(LINK => '</foo.js>; rel=preload; as=script')
        'OK'
      end

      r.is 'collect' do
        early_hint('/assets/app.css', :as => 'style')
        early_hint('/assets/app.js', :as => 'script')
        commit_early_hints
        'OK'
      end

      r.is 'raw' do
        early_hint('</assets/app.js>; rel=preload; as=script')
        commit_early_hints
        'OK'
      end

      r.is 'array' do
        early_hint(['</a.css>; rel=preload; as=style',
                    '</b.js>; rel=preload; as=script'])
        commit_early_hints
        'OK'
      end

      r.is 'hash' do
        early_hint(LINK => ['</a.css>; rel=preload; as=style',
                            '</b.js>; rel=preload; as=script'])
        commit_early_hints
        'OK'
      end

      r.is 'duplicate' do
        early_hint('/assets/app.css', :as => 'style')
        early_hint('/assets/app.css', :as => 'style')
        early_hint('</assets/app.css>; rel=preload; as=style')
        early_hint('/assets/app.css', :as => 'style', :crossorigin => true)
        early_hint('/assets/font.woff2', :as => 'font', :crossorigin => true)
        early_hint('/assets/font.woff2', :as => 'font', :crossorigin => true)
        commit_early_hints
        'OK'
      end

      r.is 'withdraw' do
        early_hint('/assets/app.css', :as => 'style')
        early_hint('/assets/app.js', :as => 'script')
        removed = remove_early_hints('/assets/app.css')
        response['X-Removed'] = removed.join(',')
        commit_early_hints
        'OK'
      end

      r.is 'withdraw-attrs' do
        early_hint('/assets/font.woff2', :as => 'font', :crossorigin => true)
        early_hint('/assets/font.woff2', :as => 'font')
        remove_early_hints('/assets/font.woff2', :crossorigin => true)
        commit_early_hints
        'OK'
      end

      r.is 'withdraw-brackets' do
        early_hint('/assets/app.js', :as => 'script')
        remove_early_hints('</assets/app.js>')
        result = commit_early_hints
        "#{result.inspect}"
      end

      r.is 'redirect' do
        early_hint('/assets/app.css', :as => 'style')
        early_hint('/assets/app.js', :as => 'script')
        remove_early_hints('/assets/app.css')
        r.redirect('/login')
      end

      r.is 'commit-twice' do
        early_hint('/assets/a.css', :as => 'style')
        first = commit_early_hints
        early_hint('/assets/b.css', :as => 'style')
        second = commit_early_hints
        "#{first[LINK].length}:#{second[LINK].length}"
      end

      r.is 'collect-after-commit-without-second-commit' do
        early_hint('/assets/a.css', :as => 'style')
        commit_early_hints
        early_hint('/assets/b.css', :as => 'style')
        'OK'
      end

      r.is 'commit-empty' do
        result = commit_early_hints
        "#{result.inspect}"
      end

      r.is 'no-callback' do
        early_hint('/assets/app.css', :as => 'style')
        early_hint('/assets/app.js', :as => 'script')
        remove_early_hints('/assets/app.js')
        result = commit_early_hints
        "#{result.inspect}"
      end
    end
  end

  it "keeps the immediate send_early_hints interface" do
    queue = []
    app(:early_hints) do |r|
      send_early_hints('link' => '</foo.js>; rel=preload; as=script')
      queue << 'OK'
      'OK'
    end

    body.must_equal 'OK'
    queue.must_equal ['OK']

    queue = []
    body('rack.early_hints' => proc{|h| queue << h}).must_equal 'OK'
    queue.must_equal [{'link' => '</foo.js>; rel=preload; as=script'}, 'OK']
  end

  it "commits buffered hints as a single early hints response" do
    early_hints_app
    sent = []
    body('/collect', 'rack.early_hints' => proc{|h| sent << h})
    sent.must_equal [{LINK => [
      "</assets/app.css>; rel=preload; as=style",
      "</assets/app.js>; rel=preload; as=script"
    ]}]
  end

  it "parses raw Link values accurately" do
    early_hints_app
    sent = []
    body('/raw', 'rack.early_hints' => proc{|h| sent << h})
    sent.must_equal [{LINK => ["</assets/app.js>; rel=preload; as=script"]}]
  end

  it "commits arrays of Link values accurately" do
    early_hints_app
    sent = []
    body('/array', 'rack.early_hints' => proc{|h| sent << h})
    sent.must_equal [{LINK => [
      "</a.css>; rel=preload; as=style",
      "</b.js>; rel=preload; as=script"
    ]}]
  end

  it "commits Link values given in a hash accurately" do
    early_hints_app
    sent = []
    body('/hash', 'rack.early_hints' => proc{|h| sent << h})
    sent.must_equal [{LINK => [
      "</a.css>; rel=preload; as=style",
      "</b.js>; rel=preload; as=script"
    ]}]
  end

  it "deduplicates identical targets and attributes but keeps differing attributes" do
    early_hints_app
    sent = []
    body('/duplicate', 'rack.early_hints' => proc{|h| sent << h})
    sent.length.must_equal 1
    sent.first[LINK].must_equal [
      "</assets/app.css>; rel=preload; as=style",
      "</assets/app.css>; rel=preload; as=style; crossorigin",
      "</assets/font.woff2>; rel=preload; as=font; crossorigin"
    ]
  end

  it "withdraws all buffered hints for a target and returns the removed values" do
    early_hints_app
    sent = []
    headers = req('/withdraw', 'rack.early_hints' => proc{|h| sent << h})[1]
    sent.must_equal [{LINK => ["</assets/app.js>; rel=preload; as=script"]}]
    headers['X-Removed'].must_equal "</assets/app.css>; rel=preload; as=style"
  end

  it "withdraws only matching attributes for a target" do
    early_hints_app
    sent = []
    body('/withdraw-attrs', 'rack.early_hints' => proc{|h| sent << h})
    sent.must_equal [{LINK => ["</assets/font.woff2>; rel=preload; as=font"]}]
  end

  it "accepts angle-bracket targets when withdrawing and returns nil for an empty commit" do
    early_hints_app
    sent = []
    body('/withdraw-brackets', 'rack.early_hints' => proc{|h| sent << h}).must_equal "nil"
    sent.must_equal []
  end

  it "does not send committed hints from a branch that later redirects" do
    early_hints_app
    sent = []
    status, response = nil
    status, response, response_body = req('/redirect', 'rack.early_hints' => proc{|h| sent << h})
    response_body.each{|_|}
    response_body.close if response_body.respond_to?(:close)
    status.must_equal 302
    response['location'].must_equal '/login'
    sent.must_equal []
  end

  it "starts a fresh buffer after each commit" do
    early_hints_app
    sent = []
    body('/commit-twice', 'rack.early_hints' => proc{|h| sent << h}).must_equal "1:1"
    sent.must_equal [
      {LINK => ["</assets/a.css>; rel=preload; as=style"]},
      {LINK => ["</assets/b.css>; rel=preload; as=style"]}
    ]
  end

  it "holds hints collected after a commit until another explicit commit" do
    early_hints_app
    sent = []
    body('/collect-after-commit-without-second-commit', 'rack.early_hints' => proc{|h| sent << h})
    sent.must_equal [{LINK => ["</assets/a.css>; rel=preload; as=style"]}]
  end

  it "returns nil when committing an empty buffer" do
    early_hints_app
    body('/commit-empty').must_equal "nil"
  end

  it "works without a rack.early_hints callback and still returns the page" do
    early_hints_app
    body('/no-callback').must_equal "nil"
  end

  it "keeps separate buffers across requests on a frozen app" do
    app(:early_hints) do |r|
      early_hint('/assets/app.css', :as => 'style')
      commit_early_hints
      'OK'
    end
    app.freeze

    2.times do
      sent = []
      body('/', 'rack.early_hints' => proc{|h| sent << h})
      sent.must_equal [{LINK => ["</assets/app.css>; rel=preload; as=style"]}]
    end
  end
end
