# frozen_string_literal: true

RSpec.describe JWT::Claims::TimeRelations do
  let(:now) { 1_000.0 }

  def verify(payload, **config)
    JWT::Claims::TimeRelations.new(now: now, **config).verify!(context: SpecSupport::Token.new(payload: payload))
  end

  describe 'ordering relations' do
    # Each row holds [earlier_value, later_value, leeway, expected_result]
    boundary_cases = [
      [100, 200, 0, :pass],
      [200, 200, 0, :pass],
      [201, 200, 0, :fail],
      [205, 200, 5, :pass],
      [206, 200, 5, :fail],
      [200.5, 200.75, 0, :pass],
      [200.5, 200.5, 0, :pass],
      [200.5, 200.25, 0.25, :pass],
      [200.51, 200.25, 0.25, :fail]
    ].freeze

    {
      iat_before_nbf: %w[iat nbf],
      nbf_before_exp: %w[nbf exp],
      iat_before_exp: %w[iat exp]
    }.each do |relation, (earlier, later)|
      describe relation do
        boundary_cases.each_with_index do |(earlier_value, later_value, leeway, expected), index|
          it "behaves as expected for boundary row #{index}" do
            payload = { earlier => earlier_value, later => later_value }
            config = { relation => { leeway: leeway } }

            if expected == :pass
              expect { verify(payload, **config) }.not_to raise_error
            else
              expect { verify(payload, **config) }.to raise_error(JWT::InvalidTimeRelation) do |error|
                expect(error.relation).to eq(relation)
                expect(error.message).to include(earlier).and include(later)
              end
            end
          end
        end

        it 'ignores a missing claim by default' do
          expect { verify({ earlier => 100 }, relation => true) }.not_to raise_error
          expect { verify({ later => 200 }, relation => true) }.not_to raise_error
          expect { verify({}, order: true) }.not_to raise_error
        end

        it 'reports the failed relation when a claim is required and missing' do
          expect { verify({}, relation => { required: true }) }.to raise_error(JWT::InvalidTimeRelation) do |error|
            expect(error.relation).to eq(relation)
            expect(error.message).to include('missing required').and include(relation.to_s)
          end
        end

        it 'is enabled through the order shortcut' do
          expect { verify({ earlier => 201, later => 200 }, order: true) }.to raise_error(JWT::InvalidTimeRelation) do |error|
            expect(error.relation).to eq(relation)
          end
        end
      end
    end
  end

  describe 'span relations' do
    # Each row holds [later_value, earlier_value, max, leeway, expected_result]
    boundary_cases = [
      [3600, 0, 3600, 0, :pass],
      [3601, 0, 3600, 0, :fail],
      [3605, 0, 3600, 5, :pass],
      [3606, 0, 3600, 5, :fail],
      [10.5, 10.0, 0.5, 0, :pass],
      [10.6, 10.0, 0.5, 0, :fail],
      [10.75, 10.0, 0.5, 0.25, :pass],
      [10.76, 10.0, 0.5, 0.25, :fail],
      [-100, 0, 10, 0, :pass]
    ].freeze

    {
      max_lifetime: %w[iat exp],
      max_validity: %w[nbf exp]
    }.each do |relation, (earlier, later)|
      describe relation do
        boundary_cases.each_with_index do |(later_value, earlier_value, max, leeway, expected), index|
          it "behaves as expected for boundary row #{index}" do
            payload = { earlier => earlier_value, later => later_value }
            config = { relation => { max: max, leeway: leeway } }

            if expected == :pass
              expect { verify(payload, **config) }.not_to raise_error
            else
              expect { verify(payload, **config) }.to raise_error(JWT::InvalidTimeRelation) do |error|
                expect(error.relation).to eq(relation)
                expect(error.message).to include('exceeds the maximum')
              end
            end
          end
        end

        it 'ignores a missing claim by default' do
          expect { verify({ later => 100 }, relation => { max: 10 }) }.not_to raise_error
        end

        it 'reports the failed relation when a claim is required and missing' do
          expect { verify({}, relation => { max: 10, required: true }) }.to raise_error(JWT::InvalidTimeRelation) do |error|
            expect(error.relation).to eq(relation)
          end
        end

        it 'requires a max at construction time' do
          expect { JWT::Claims::TimeRelations.new(relation => {}) }.to raise_error(ArgumentError, /requires a :max/)
        end
      end
    end
  end

  describe ':max_future_iat' do
    # Each row holds [iat_value, clock_value, leeway, expected_result]
    boundary_cases = [
      [1_000, 1_000, 0, :pass],
      [1_001, 1_000, 0, :fail],
      [1_005, 1_000, 5, :pass],
      [1_006, 1_000, 5, :fail],
      [1_000.25, 1_000.0, 0.25, :pass],
      [1_000.26, 1_000.0, 0.25, :fail],
      [900, 1_000, 0, :pass]
    ].freeze

    boundary_cases.each_with_index do |(iat_value, clock_value, leeway, expected), index|
      it "behaves as expected for boundary row #{index}" do
        action = lambda do
          JWT::Claims::TimeRelations.new(now: clock_value, max_future_iat: { leeway: leeway })
                       .verify!(context: SpecSupport::Token.new(payload: { 'iat' => iat_value }))
        end

        if expected == :pass
          expect(&action).not_to raise_error
        else
          expect(&action).to raise_error(JWT::InvalidTimeRelation) do |error|
            expect(error.relation).to eq(:max_future_iat)
            expect(error.message).to include('too far in the future')
          end
        end
      end
    end

    it 'ignores a missing iat by default' do
      expect { verify({}, max_future_iat: true) }.not_to raise_error
    end

    it 'reports the relation when iat is required and missing' do
      expect { verify({}, max_future_iat: { required: true }) }.to raise_error(JWT::InvalidTimeRelation) do |error|
        expect(error.relation).to eq(:max_future_iat)
      end
    end
  end

  describe 'malformed claim values' do
    {
      iat_before_nbf: { payload: { 'iat' => '100', 'nbf' => 200 }, config: { order: true } },
      nbf_before_exp: { payload: { 'nbf' => 100, 'exp' => '200' }, config: { order: true } },
      iat_before_exp: { payload: { 'iat' => 100, 'exp' => true }, config: { order: true } },
      max_lifetime_infinity: { payload: { 'iat' => 0, 'exp' => Float::INFINITY }, config: { max_lifetime: { max: 100 } } },
      max_lifetime_nan: { payload: { 'iat' => Float::NAN, 'exp' => 100 }, config: { max_lifetime: { max: 100 } } },
      max_validity_neg_infinity: { payload: { 'nbf' => 100, 'exp' => -Float::INFINITY }, config: { max_validity: { max: 100 } } },
      future_iat_infinity: { payload: { 'iat' => Float::INFINITY }, config: { max_future_iat: {} },
                             relation: :max_future_iat }
    }.each do |name, data|
      it "rejects #{name}" do
        expect { verify(data[:payload], **data[:config]) }.to raise_error(JWT::InvalidTimeRelation) do |error|
          expect(error.relation).to eq(data[:relation]) if data[:relation]
          expect(error.message).to include('must be a finite Numeric')
        end
      end
    end
  end

  describe 'single injected time and leeway' do
    it 'applies the order shortcut options to every ordering relation' do
      payload = { 'iat' => 203, 'nbf' => 200, 'exp' => 203 }
      expect { verify(payload, order: { leeway: 3 }) }.not_to raise_error

      payload = { 'iat' => 204, 'nbf' => 200, 'exp' => 203 }
      expect { verify(payload, order: { leeway: 3 }) }.to raise_error(JWT::InvalidTimeRelation) do |error|
        expect(error.relation).to eq(:iat_before_nbf)
      end
    end

    it 'makes claims required for every ordering relation via the shortcut' do
      expect { verify({ 'iat' => 1, 'exp' => 2 }, order: { required: true }) }
        .to raise_error(JWT::InvalidTimeRelation) { |error| expect(error.relation).to eq(:iat_before_nbf) }
    end

    it 'evaluates every relation against the same value returned by the clock' do
      calls = 0
      clock = lambda do
        calls += 1
        1_000
      end
      payload = { 'iat' => 990, 'nbf' => 995, 'exp' => 3_590 }

      described_class.new(now: clock,
                          order: true,
                          max_lifetime: { max: 2600, leeway: 10 },
                          max_validity: { max: 2600, leeway: 10 },
                          max_future_iat: { leeway: 10 })
                    .verify!(context: SpecSupport::Token.new(payload: payload))

      expect(calls).to eq(1)
    end

    it 'accepts a Time object as the injected time' do
      expect do
        verify({ 'iat' => 1_000 }, max_future_iat: {}, now: Time.at(1_000))
      end.not_to raise_error
    end

    it 'does not stack a global and a relation leeway' do
      # iat is 3 past exp. With a single leeway of 4 the gap is tolerated;
      # if global and relation leeway were added, 4 would not be needed at all.
      payload = { 'iat' => 203, 'exp' => 200 }
      expect { verify(payload, leeway: 4, iat_before_exp: { leeway: 4 }) }.not_to raise_error
      expect { verify(payload, leeway: 2, iat_before_exp: { leeway: 4 }) }.not_to raise_error
      expect { verify(payload, leeway: 2, iat_before_exp: { leeway: 1 }) }.to raise_error(JWT::InvalidTimeRelation)
      expect { verify(payload, leeway: 4, iat_before_exp: {}) }.not_to raise_error
      expect { verify(payload, leeway: 1, iat_before_exp: {}) }.to raise_error(JWT::InvalidTimeRelation)
    end

    it 'raises for a non-numeric injected time' do
      expect { JWT::Claims::TimeRelations.new(now: 'soon') }
        .not_to raise_error
      expect { verify({ 'iat' => 1 }, max_future_iat: {}, now: 'soon') }
        .to raise_error(ArgumentError, /finite Numeric or Time/)
    end

    it 'raises for unknown configuration keys' do
      expect { JWT::Claims::TimeRelations.new(unknown_relation: true) }.to raise_error(ArgumentError, /unknown time relation option/)
    end
  end

  describe 'composition with JWT::Claims' do
    let(:payload) { { 'iat' => 200, 'nbf' => 100, 'exp' => 150 } }

    it 'is reached via the :time_relations verifier key and defaults to ordering' do
      expect { JWT::Claims.verify_payload!(payload, :time_relations) }
        .to raise_error(JWT::InvalidTimeRelation) { |error| expect(error.relation).to eq(:iat_before_nbf) }
    end

    it 'surfaces as an error from the predicate API' do
      errors = JWT::Claims.payload_errors(payload, time_relations: { order: true })
      relations = errors.map { |error| error.message }
      expect(relations.first).to include('iat claim must not be later than nbf claim')
    end

    it 'runs without error when the relations hold' do
      JWT::Claims.verify_payload!({ 'iat' => 0, 'nbf' => 1, 'exp' => 2 }, time_relations: { order: true })
    end
  end
end
