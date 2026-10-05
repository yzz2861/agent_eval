# frozen_string_literal: true

RSpec.describe Faraday::Batch do
  describe Faraday::Batch::Part do
    it 'preserves method, relative target, headers and body' do
      part = described_class.new(:post, '/items?x=1', 'body',
                                 { 'Content-Type' => 'text/plain' }, id: 'p1')

      expect(part.id).to eq('p1')
      expect(part.method).to eq(:post)
      expect(part.url).to eq('/items?x=1')
      expect(part.headers['Content-Type']).to eq('text/plain')
      expect(part.body).to eq('body')
    end

    it 'normalizes string methods to lowercase symbols' do
      expect(described_class.new('GET', '/a').method).to eq(:get)
    end

    it 'generates a unique Content-ID when none is given' do
      first = described_class.new(:get, '/a')
      second = described_class.new(:get, '/a')

      expect(first.id).to start_with('item-')
      expect(first.id).not_to eq(second.id)
    end
  end

  describe Faraday::Batch::Request do
    subject(:batch) { described_class.new }

    it 'adds parts in order and enumerates them' do
      batch.request(:get, '/a', nil, {}, id: 'a')
      batch.request(:get, '/b', nil, {}, id: 'b')

      expect(batch.size).to eq(2)
      expect(batch.ids).to eq(%w[a b])
      expect(batch.map(&:id)).to eq(%w[a b])
    end

    it 'rejects duplicate ids' do
      batch.request(:get, '/a', nil, {}, id: 'dup')
      expect { batch.request(:get, '/b', nil, {}, id: 'dup') }
        .to raise_error(Faraday::Batch::DuplicateIdError)
    end

    it 'accepts parts built independently' do
      part = Faraday::Batch::Part.new(:get, '/c', nil, {}, id: 'c')
      batch.add(part)
      expect(batch.ids).to eq(%w[c])
    end
  end

  describe Faraday::Batch::Response do
    def result(id, status, error = nil)
      Faraday::Batch::Result.new(id, status, {}, 'body', error)
    end

    it 'orders by expected ids and fills missing ones' do
      response = described_class.new(%w[a b], {
        'b' => result('b', 200)
      }, outer_status: 200)

      expect(response.map(&:id)).to eq(%w[a b])
      expect(response['a']).to be_missing
      expect(response['a'].error).to be_a(Faraday::Batch::MissingResponseError)
      expect(response.missing.map(&:id)).to eq(%w[a])
    end

    it 'is only successful when every item is 2xx' do
      response = described_class.new(%w[a b], {
        'a' => result('a', 200),
        'b' => result('b', 302)
      }, outer_status: 200)

      expect(response).not_to be_success
      expect(response.failed.map(&:id)).to eq(%w[b])
    end
  end
end
