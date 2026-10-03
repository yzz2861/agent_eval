# frozen_string_literal: true

RSpec.describe JWT::Claims::Timing do
  NOW = Time.at(1_700_000_000)
  NOW_F = NOW.to_f

  let(:options) { {} }
  let(:payload) { {} }

  subject(:verify!) { described_class.new(**options).verify!(context: SpecSupport::Token.new(payload: payload)) }

  shared_examples 'timing relation boundaries' do |relation, rows|
    rows.each do |row|
      context "when #{row[:description]}" do
        let(:options) { row[:options] }
        let(:payload) { row[:payload] }

        if row[:valid]
          it 'passes validation' do
            verify!
          end
        else
          it "raises JWT::InvalidTimingError naming the #{relation} relation" do
            expect { verify! }.to raise_error(JWT::InvalidTimingError, /#{Regexp.escape(relation)}/)
          end
        end
      end
    end
  end

  describe 'max_lifetime relation' do
    include_examples 'timing relation boundaries', 'exp - iat <= max_lifetime', [
      { description: 'lifetime equals max_lifetime', options: { max_lifetime: 3600 }, payload: { 'iat' => 1000, 'exp' => 4600 }, valid: true },
      { description: 'lifetime is one second over max_lifetime', options: { max_lifetime: 3600 }, payload: { 'iat' => 1000, 'exp' => 4601 }, valid: false },
      { description: 'lifetime is a fraction over max_lifetime', options: { max_lifetime: 3600 }, payload: { 'iat' => 1000, 'exp' => 4600.5 }, valid: false },
      { description: 'lifetime is a fraction under max_lifetime', options: { max_lifetime: 3600 }, payload: { 'iat' => 1000.5, 'exp' => 4600 }, valid: true },
      { description: 'claims are numeric strings', options: { max_lifetime: 3600 }, payload: { 'iat' => '1000', 'exp' => '4601' }, valid: false },
      { description: 'leeway is given', options: { max_lifetime: 3600, leeway: 100 }, payload: { 'iat' => 1000, 'exp' => 4601 }, valid: false },
      { description: 'iat is missing', options: { max_lifetime: 3600 }, payload: { 'exp' => 4601 }, valid: true },
      { description: 'exp is missing', options: { max_lifetime: 3600 }, payload: { 'iat' => 1000 }, valid: true }
    ]
  end

  describe 'max_future_iat relation' do
    include_examples 'timing relation boundaries', 'iat - now <= max_future_iat', [
      { description: 'iat is exactly max_future_iat ahead of now', options: { now: NOW, max_future_iat: 60 }, payload: { 'iat' => NOW_F + 60 }, valid: true },
      { description: 'iat is one second further ahead', options: { now: NOW, max_future_iat: 60 }, payload: { 'iat' => NOW_F + 61 }, valid: false },
      { description: 'iat is a fraction further ahead', options: { now: NOW, max_future_iat: 60 }, payload: { 'iat' => NOW_F + 60.5 }, valid: false },
      { description: 'iat equals now', options: { now: NOW, max_future_iat: 60 }, payload: { 'iat' => NOW_F }, valid: true },
      { description: 'iat is within the leeway on top of max_future_iat', options: { now: NOW, max_future_iat: 60, leeway: 10 }, payload: { 'iat' => NOW_F + 70 }, valid: true },
      { description: 'iat is one second beyond the leeway on top of max_future_iat', options: { now: NOW, max_future_iat: 60, leeway: 10 }, payload: { 'iat' => NOW_F + 71 }, valid: false },
      { description: 'iat is a numeric string', options: { now: NOW, max_future_iat: 60 }, payload: { 'iat' => (NOW_F + 61).to_s }, valid: false },
      { description: 'iat is missing', options: { now: NOW, max_future_iat: 60 }, payload: {}, valid: true }
    ]
  end

  describe 'order relation' do
    include_examples 'timing relation boundaries', 'iat <= exp', [
      { description: 'iat equals exp', options: { order: %i[iat exp] }, payload: { 'iat' => 1000, 'exp' => 1000 }, valid: true },
      { description: 'iat is one second after exp', options: { order: %i[iat exp] }, payload: { 'iat' => 1001, 'exp' => 1000 }, valid: false },
      { description: 'iat is a fraction after exp', options: { order: %i[iat exp] }, payload: { 'iat' => 1000.5, 'exp' => 1000 }, valid: false },
      { description: 'leeway is given', options: { order: %i[iat exp], leeway: 100 }, payload: { 'iat' => 1001, 'exp' => 1000 }, valid: false },
      { description: 'claims are numeric strings', options: { order: %i[iat exp] }, payload: { 'iat' => '1001', 'exp' => '1000' }, valid: false },
      { description: 'iat is missing', options: { order: %i[iat exp] }, payload: { 'exp' => 1000 }, valid: true }
    ]

    include_examples 'timing relation boundaries', 'nbf <= exp', [
      { description: 'nbf equals exp', options: { order: %i[nbf exp] }, payload: { 'nbf' => 1000, 'exp' => 1000 }, valid: true },
      { description: 'nbf is after exp', options: { order: %i[nbf exp] }, payload: { 'nbf' => 1001, 'exp' => 1000 }, valid: false }
    ]

    context 'when a full iat, nbf, exp chain is ordered' do
      let(:options) { { order: %i[iat nbf exp] } }

      context 'when all claims are in order' do
        let(:payload) { { 'iat' => 1000, 'nbf' => 1001, 'exp' => 1002 } }

        it 'passes validation' do
          verify!
        end
      end

      context 'when a middle claim is missing' do
        let(:payload) { { 'iat' => 1000, 'exp' => 999 } }

        it 'still verifies the remaining pair' do
          expect { verify! }.to raise_error(JWT::InvalidTimingError, /iat <= exp/)
        end
      end
    end
  end

  describe 'claim values' do
    let(:options) { { order: %i[iat exp] } }

    [
      { value: 'not-a-number', description: 'a non-numeric string' },
      { value: Float::INFINITY, description: 'infinity' },
      { value: -Float::INFINITY, description: 'negative infinity' },
      { value: Float::NAN, description: 'NaN' },
      { value: Object.new, description: 'an arbitrary object' }
    ].each do |row|
      context "when iat is #{row[:description]}" do
        let(:payload) { { 'iat' => row[:value], 'exp' => 1000 } }

        it 'raises JWT::InvalidPayload' do
          expect { verify! }.to raise_error(JWT::InvalidPayload, 'iat claim must be a finite numeric value')
        end
      end
    end

    context 'when exp is a non-numeric string' do
      let(:payload) { { 'iat' => 1000, 'exp' => 'tomorrow' } }

      it 'raises JWT::InvalidPayload' do
        expect { verify! }.to raise_error(JWT::InvalidPayload, 'exp claim must be a finite numeric value')
      end
    end
  end

  describe 'required claims' do
    let(:options) { { required: %i[iat exp] } }

    context 'when a required claim is missing' do
      let(:payload) { { 'iat' => 1000 } }

      it 'raises JWT::MissingRequiredClaim' do
        expect { verify! }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end

    context 'when all required claims are present' do
      let(:payload) { { 'iat' => 1000, 'exp' => 2000 } }

      it 'passes validation' do
        verify!
      end
    end
  end

  describe 'leeway' do
    let(:options) { { now: NOW, leeway: 10, max_future_iat: 60, order: %i[iat exp] } }

    context 'when iat is within leeway of now but after exp' do
      let(:payload) { { 'iat' => NOW_F + 5, 'exp' => NOW_F } }

      it 'does not relax the order relation' do
        expect { verify! }.to raise_error(JWT::InvalidTimingError, /iat <= exp/)
      end
    end
  end

  describe 'injected current time' do
    let(:options) { { now: future_now, max_future_iat: 60 } }
    let(:future_now) { NOW_F + 3600 }
    let(:payload) { { 'iat' => NOW_F + 3600 } }

    it 'evaluates the relation against the injected moment' do
      verify!
    end

    context 'when now is not a finite numeric time' do
      let(:future_now) { 'soon' }

      it 'raises ArgumentError' do
        expect { verify! }.to raise_error(ArgumentError, 'now must be a finite numeric time')
      end
    end
  end

  describe 'policy validation' do
    it 'rejects unknown claims in the order relation' do
      expect { described_class.new(order: %i[iat foo]) }.to raise_error(ArgumentError, 'Unknown temporal claims in timing policy: foo')
    end

    it 'rejects unknown required claims' do
      expect { described_class.new(required: %i[bar]) }.to raise_error(ArgumentError, 'Unknown temporal claims in timing policy: bar')
    end
  end

  describe 'payload handling' do
    context 'when payload is not a Hash' do
      let(:payload) { 'beautyexperts_nbf_iat' }
      let(:options) { { max_lifetime: 3600 } }

      it 'passes validation' do
        verify!
      end
    end
  end

  describe 'integration with JWT::Claims.verify_payload!' do
    let(:payload) { { 'iat' => 1001, 'exp' => 1000 } }

    it 'verifies the timing relations' do
      expect { JWT::Claims.verify_payload!(payload, timing: { order: %i[iat exp] }) }
        .to raise_error(JWT::InvalidTimingError, /iat <= exp/)
    end

    it 'reports the error via JWT::Claims.payload_errors' do
      errors = JWT::Claims.payload_errors(payload, timing: { order: %i[iat exp] })
      expect(errors.map(&:message)).to include(a_string_matching(/iat <= exp/))
    end

    it 'accepts a valid payload' do
      expect(JWT::Claims.valid_payload?({ 'iat' => 1000, 'exp' => 1001 }, timing: { order: %i[iat exp] })).to be(true)
    end
  end
end
