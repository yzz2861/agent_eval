# frozen_string_literal: true

RSpec.describe Faraday::Response::Multistatus, type: :response do
  let(:options) { {} }
  let(:headers) { {} }
  let(:request_url) { 'http://example.com/dir/' }
  let(:middleware) do
    described_class.new(lambda { |env|
      Faraday::Response.new(env)
    }, **options)
  end

  def process(body, content_type = 'application/xml', options = {})
    env = {
      body: body, request: options,
      url: URI(request_url),
      request_headers: Faraday::Utils::Headers.new,
      response_headers: Faraday::Utils::Headers.new(headers)
    }
    env[:response_headers]['content-type'] = content_type if content_type
    yield(env) if block_given?
    middleware.call(Faraday::Env.from(env))
  end

  let(:multistatus_body) do
    <<~XML
      <?xml version="1.0" encoding="utf-8"?>
      <D:multistatus xmlns:D="DAV:" xmlns:Z="http://example.com/ns">
        <D:response>
          <D:href>file1.txt</D:href>
          <D:propstat>
            <D:prop>
              <D:getcontentlength>1234</D:getcontentlength>
              <D:resourcetype><D:collection/></D:resourcetype>
              <Z:rating>5</Z:rating>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
          </D:propstat>
          <D:propstat>
            <D:prop>
              <D:displayname/>
              <Z:displayname>zed</Z:displayname>
            </D:prop>
            <D:status>HTTP/1.1 404 Not Found</D:status>
            <D:responsedescription>Property not found</D:responsedescription>
          </D:propstat>
        </D:response>
        <D:response>
          <D:href>http://example.com/dir/file2.txt</D:href>
          <D:status>HTTP/1.1 403 Forbidden</D:status>
          <D:responsedescription>Not allowed</D:responsedescription>
        </D:response>
      </D:multistatus>
    XML
  end

  it 'is registered as :multistatus middleware' do
    expect(Faraday::Response.lookup_middleware(:multistatus)).to eq(described_class)
  end

  context 'no type matching' do
    it "doesn't change nil body" do
      expect(process(nil).body).to be_nil
    end

    it "doesn't change empty body" do
      expect(process('').body).to eq('')
    end

    it 'parses a multistatus body into a Result' do
      result = process(multistatus_body).body
      expect(result).to be_a(described_class::Result)
      expect(result.size).to eq(2)
    end
  end

  context 'with default regexp type matching' do
    it 'parses text/xml bodies' do
      expect(process(multistatus_body, 'text/xml').body).to be_a(described_class::Result)
    end

    it 'parses +xml suffixed types' do
      expect(process(multistatus_body, 'application/webdav+xml').body).to be_a(described_class::Result)
    end

    it 'parses content types with parameters' do
      expect(process(multistatus_body, 'application/xml; charset="utf-8"').body).to be_a(described_class::Result)
    end

    it 'ignores bodies of incorrect type' do
      expect(process(multistatus_body, 'application/json').body).to eq(multistatus_body)
    end
  end

  context 'with non-multistatus XML' do
    it 'leaves the body untouched' do
      expect(process('<html><body>hi</body></html>').body).to eq('<html><body>hi</body></html>')
    end
  end

  context 'with preserving raw' do
    let(:options) { { preserve_raw: true } }

    it 'keeps the raw body around' do
      response = process(multistatus_body)
      expect(response.body).to be_a(described_class::Result)
      expect(response.env[:raw_body]).to eq(multistatus_body)
    end
  end

  describe 'resource organization' do
    subject(:result) { process(multistatus_body).body }

    it 'keys resources by absolute href, resolving relative hrefs against the request URI' do
      expect(result.resources.keys).to contain_exactly(
        'http://example.com/dir/file1.txt',
        'http://example.com/dir/file2.txt'
      )
    end

    it 'resolves root-relative hrefs against the request URI' do
      body = multistatus_body.sub('<D:href>file1.txt</D:href>', '<D:href>/other/file1.txt</D:href>')
      expect(process(body).body.resources.keys).to include('http://example.com/other/file1.txt')
    end

    it 'keeps the resource-level status and description' do
      resource = result['http://example.com/dir/file2.txt']
      expect(resource.status).to eq('HTTP/1.1 403 Forbidden')
      expect(resource.status_code).to eq(403)
      expect(resource.response_description).to eq('Not allowed')
      expect(resource.propstats).to be_empty
    end
  end

  describe 'propstat parsing' do
    subject(:resource) { process(multistatus_body).body['http://example.com/dir/file1.txt'] }

    it 'keeps one PropStat per propstat element, each with its own status' do
      expect(resource.propstats.size).to eq(2)
      expect(resource.propstats.map(&:status)).to eq(['HTTP/1.1 200 OK', 'HTTP/1.1 404 Not Found'])
      expect(resource.propstats.map(&:status_code)).to eq([200, 404])
      expect(resource.propstats.map(&:ok?)).to eq([true, false])
    end

    it 'keeps the propstat error description' do
      expect(resource.propstats[1].response_description).to eq('Property not found')
    end

    it 'identifies properties by expanded name' do
      propstat = resource.propstats[0]
      expect(propstat.properties.keys).to contain_exactly(
        '{DAV:}getcontentlength', '{DAV:}resourcetype', '{http://example.com/ns}rating'
      )
      expect(propstat['{DAV:}getcontentlength'].value).to eq('1234')
      expect(propstat['{http://example.com/ns}rating'].value).to eq('5')
    end

    it 'does not merge same-named properties from different namespaces' do
      propstat = resource.propstats[1]
      expect(propstat['{DAV:}displayname'].value).to be_nil
      expect(propstat['{http://example.com/ns}displayname'].value).to eq('zed')
    end

    it 'exposes nested elements as child properties' do
      resourcetype = resource.propstats[0]['{DAV:}resourcetype']
      expect(resourcetype.children.map(&:expanded_name)).to eq(['{DAV:}collection'])
    end
  end

  describe 'duplicate resources' do
    let(:multistatus_body) do
      <<~XML
        <D:multistatus xmlns:D="DAV:">
          <D:response>
            <D:href>/dir/dup.txt</D:href>
            <D:propstat>
              <D:prop><D:getcontentlength>1</D:getcontentlength></D:prop>
              <D:status>HTTP/1.1 200 OK</D:status>
            </D:propstat>
          </D:response>
          <D:response>
            <D:href>/dir/dup.txt</D:href>
            <D:propstat>
              <D:prop><D:getetag>"abc"</D:getetag></D:prop>
              <D:status>HTTP/1.1 200 OK</D:status>
            </D:propstat>
          </D:response>
        </D:multistatus>
      XML
    end

    it 'merges them into a single resource, appending propstats in document order' do
      result = process(multistatus_body).body
      expect(result.size).to eq(1)

      resource = result['http://example.com/dir/dup.txt']
      expect(resource.propstats.size).to eq(2)
      expect(resource.propstats[0]['{DAV:}getcontentlength'].value).to eq('1')
      expect(resource.propstats[1]['{DAV:}getetag'].value).to eq('"abc"')
    end
  end

  describe 'XML safety' do
    it 'rejects documents with a DOCTYPE declaration' do
      body = <<~XML
        <?xml version="1.0"?>
        <!DOCTYPE multistatus [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <D:multistatus xmlns:D="DAV:"/>
      XML
      expect { process(body) }.to raise_error(Faraday::ParsingError, /DOCTYPE/)
    end

    it 'rejects documents defining external entities' do
      body = <<~XML
        <!DOCTYPE D:multistatus [<!ENTITY xxe SYSTEM "http://evil.example.com/x">]>
        <D:multistatus xmlns:D="DAV:"/>
      XML
      expect { process(body) }.to raise_error(Faraday::ParsingError)
    end

    it 'raises ParsingError on malformed XML' do
      expect { process('<D:multistatus xmlns:D="DAV:">') }.to raise_error(Faraday::ParsingError)
    end
  end
end
