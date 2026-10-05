# frozen_string_literal: true

RSpec.describe Faraday::Response::Multistatus, type: :response do
  let(:options) { {} }
  let(:headers) { {} }
  let(:middleware) do
    described_class.new(lambda { |env|
      Faraday::Response.new(env)
    }, **options)
  end

  def process(body, content_type = 'application/xml', options = {})
    env = {
      status: 207,
      url: Faraday::Utils.URI('https://dav.example.com/container/'),
      request: options,
      request_headers: Faraday::Utils::Headers.new,
      response_headers: Faraday::Utils::Headers.new(headers)
    }
    env[:response_headers]['content-type'] = content_type if content_type
    yield(env) if block_given?
    faraday_env = Faraday::Env.from(env)
    faraday_env[:body] = body
    middleware.call(faraday_env)
  end

  let(:multistatus_body) do
    <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <D:multistatus xmlns:D="DAV:" xmlns:R="http://example.com/ns">
        <D:response>
          <D:href>/container/file.txt</D:href>
          <D:propstat>
            <D:prop>
              <D:displayname>file.txt</D:displayname>
              <R:displayname>renamed.txt</R:displayname>
              <D:getcontentlength>42</D:getcontentlength>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
          </D:propstat>
          <D:propstat>
            <D:prop>
              <D:getcontenttype/>
            </D:prop>
            <D:status>HTTP/1.1 404 Not Found</D:status>
            <D:error><D:prop-not-found/></D:error>
            <D:responsedescription>Property not supported</D:responsedescription>
          </D:propstat>
        </D:response>
        <D:response>
          <D:href>https://dav.example.com/other/</D:href>
          <D:propstat>
            <D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
          </D:propstat>
        </D:response>
      </D:multistatus>
    XML
  end

  context 'with a 207 multi-status response' do
    subject(:result) { process(multistatus_body).body }

    it 'returns a Result keyed by absolute href' do
      expect(result).to be_a(Faraday::Response::Multistatus::Result)
      expect(result.size).to eq(2)
      expect(result.resources.keys).to eq(
        ['https://dav.example.com/container/file.txt', 'https://dav.example.com/other/']
      )
    end

    it 'resolves relative hrefs against the request URI' do
      resource = result['https://dav.example.com/container/file.txt']
      expect(resource.href).to eq('https://dav.example.com/container/file.txt')
    end

    it 'identifies properties by expanded name without merging namespaces' do
      properties = result['https://dav.example.com/container/file.txt'].properties
      expect(properties['{DAV:}displayname']).to eq('file.txt')
      expect(properties['{http://example.com/ns}displayname']).to eq('renamed.txt')
      expect(properties['{DAV:}getcontentlength']).to eq('42')
    end

    it 'stores nil for properties without text content' do
      properties = result['https://dav.example.com/other/'].properties
      expect(properties).to have_key('{DAV:}resourcetype')
      expect(properties['{DAV:}resourcetype']).to be_nil
    end

    it 'keeps each propstat with its own status and error details' do
      propstats = result['https://dav.example.com/container/file.txt'].propstats
      expect(propstats.size).to eq(2)

      expect(propstats[0].status).to eq('HTTP/1.1 200 OK')
      expect(propstats[0].status_code).to eq(200)
      expect(propstats[0].error).to be_nil

      expect(propstats[1].status).to eq('HTTP/1.1 404 Not Found')
      expect(propstats[1].status_code).to eq(404)
      expect(propstats[1].response_description).to eq('Property not supported')
      expect(propstats[1].properties).to eq('{DAV:}getcontenttype' => nil)
    end

    it 'merges duplicate hrefs by appending propstats in document order' do
      body = <<~XML
        <D:multistatus xmlns:D="DAV:">
          <D:response>
            <D:href>/container/a</D:href>
            <D:propstat>
              <D:prop><D:displayname>a</D:displayname></D:prop>
              <D:status>HTTP/1.1 200 OK</D:status>
            </D:propstat>
          </D:response>
          <D:response>
            <D:href>https://dav.example.com/container/a</D:href>
            <D:propstat>
              <D:prop><D:getcontentlength>1</D:getcontentlength></D:prop>
              <D:status>HTTP/1.1 200 OK</D:status>
            </D:propstat>
          </D:response>
        </D:multistatus>
      XML
      merged = process(body).body
      expect(merged.size).to eq(1)
      resource = merged['https://dav.example.com/container/a']
      expect(resource.propstats.size).to eq(2)
      expect(resource.properties).to eq(
        '{DAV:}displayname' => 'a', '{DAV:}getcontentlength' => '1'
      )
    end

    it 'exposes the top-level responsedescription' do
      body = <<~XML
        <D:multistatus xmlns:D="DAV:">
          <D:responsedescription>Partial failure</D:responsedescription>
          <D:response>
            <D:href>/container/a</D:href>
            <D:error><D:lock-token-submitted/></D:error>
            <D:responsedescription>Locked</D:responsedescription>
          </D:response>
        </D:multistatus>
      XML
      parsed = process(body).body
      expect(parsed.response_description).to eq('Partial failure')
      resource = parsed['https://dav.example.com/container/a']
      expect(resource.response_description).to eq('Locked')
      expect(resource.propstats).to be_empty
    end
  end

  context 'with status and content-type matching' do
    it 'ignores responses with a non-matching status' do
      response = process(multistatus_body) { |env| env[:status] = 200 }
      expect(response.body).to eq(multistatus_body)
    end

    context 'with a custom statuses option' do
      let(:options) { { statuses: [200] } }

      it 'parses responses with the configured status' do
        response = process(multistatus_body) { |env| env[:status] = 200 }
        expect(response.body).to be_a(Faraday::Response::Multistatus::Result)
      end
    end

    it 'ignores bodies with a non-matching content type' do
      response = process(multistatus_body, 'text/html')
      expect(response.body).to eq(multistatus_body)
    end

    it 'parses text/xml bodies' do
      response = process(multistatus_body, 'text/xml; charset="utf-8"')
      expect(response.body).to be_a(Faraday::Response::Multistatus::Result)
    end

    it "doesn't change nil body" do
      expect(process(nil).body).to be_nil
    end

    it 'nullifies empty body' do
      expect(process('').body).to be_nil
    end
  end

  context 'with preserve_raw' do
    let(:options) { { preserve_raw: true } }

    it 'keeps the raw body around' do
      response = process(multistatus_body)
      expect(response.body).to be_a(Faraday::Response::Multistatus::Result)
      expect(response.env[:raw_body]).to eq(multistatus_body)
    end
  end

  context 'with unsafe or malformed XML' do
    it 'rejects bodies with a DOCTYPE declaration' do
      body = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE multistatus [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <D:multistatus xmlns:D="DAV:">
          <D:response><D:href>/container/a</D:href>
            <D:propstat><D:prop><D:displayname>&xxe;</D:displayname></D:prop>
            <D:status>HTTP/1.1 200 OK</D:status></D:propstat>
          </D:response>
        </D:multistatus>
      XML
      expect { process(body) }.to raise_error(Faraday::ParsingError, /DOCTYPE/)
    end

    it 'rejects external DTD references' do
      body = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE multistatus SYSTEM "http://evil.example.com/x.dtd">
        <D:multistatus xmlns:D="DAV:"/>
      XML
      expect { process(body) }.to raise_error(Faraday::ParsingError, /DOCTYPE/)
    end

    it 'raises ParsingError on malformed XML' do
      expect { process('<D:multistatus') }.to raise_error(Faraday::ParsingError)
    end

    it 'raises ParsingError when the root element is not multistatus' do
      expect { process('<html></html>') }.to raise_error(Faraday::ParsingError)
    end
  end

  it 'is registered as :multistatus middleware' do
    expect(Faraday::Response.lookup_middleware(:multistatus)).to eq(described_class)
  end
end
