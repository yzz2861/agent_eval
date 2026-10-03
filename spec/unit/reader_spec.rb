# frozen_string_literal: true

RSpec.describe(Dry::Monads::Reader) do
  include Dry::Monads[:reader]

  describe "construction" do
    it "wraps a block receiving the environment" do
      expect(Reader { |env| env + 1 }.run(1)).to eql(2)
    end

    it "wraps a positional callable" do
      fn = ->(env) { env * 3 }

      expect(Reader(fn).run(4)).to eql(12)
    end

    it "converts a symbol into a proc" do
      expect(Reader(:to_s).run(7)).to eql("7")
    end

    it "raises when given a non-callable" do
      expect { described_class.new(123) }.to raise_error(TypeError, /not callable/)
    end

    it "raises when neither a block nor a callable is given" do
      expect { described_class.new }.to raise_error(ArgumentError, /callable is required/)
    end
  end

  describe ".pure" do
    it "ignores the environment and always returns the lifted value" do
      reader = described_class.pure(42)

      expect(reader.run(:one)).to eql(42)
      expect(reader.run(:two)).to eql(42)
    end

    it "accepts a block as the value" do
      fn = ->(x) { x + 1 }

      expect(described_class.pure(&fn).run(nil)).to be(fn)
    end
  end

  describe ".ask" do
    it_behaves_like "a monad" do
      subject { described_class.ask }
    end

    it "returns the environment unchanged" do
      env = { db: :primary }

      expect(described_class.ask.run(env)).to be(env)
    end

    it "exposes ask on instances" do
      expect(described_class.pure(1).ask.run(:env)).to be(:env)
    end
  end

  describe "#run" do
    it "is aliased as #call" do
      reader = Reader { |env| env }

      expect(reader.method(:call)).to eql(reader.method(:run))
    end

    it "builds once and runs against two different environments" do
      reader = described_class.ask.fmap { |env| env[:name] }

      expect(reader.run(name: "Anna")).to eql("Anna")
      expect(reader.run(name: "Bjorn")).to eql("Bjorn")
    end

    it "reads the environment at run time, not at build time" do
      env = { count: 1 }
      reader = described_class.ask.fmap { |e| e[:count] }
      env[:count] = 2

      expect(reader.run(env)).to eql(2)
    end

    it "does not turn exceptions into Failure" do
      reader = described_class.ask.fmap { raise "boom" }

      expect { reader.run(:env) }.to raise_error(RuntimeError, "boom")
    end

    it "propagates exceptions from a bind/fmap chain" do
      reader =
        described_class.ask
                       .bind { described_class.pure(1) }
                       .fmap { raise "nope" }

      expect { reader.run(:env) }.to raise_error(RuntimeError, "nope")
    end
  end

  describe "#fmap" do
    it "accepts a callable just like a block" do
      block_form = described_class.ask.fmap(&:inspect)
      callable_form = described_class.ask.fmap(:inspect.to_proc)

      samples = [1, :sym, "str", nil].freeze
      samples.each do |env|
        expect(callable_form.run(env)).to eql(block_form.run(env))
      end
    end

    it "transforms the result lazily" do
      called = 0
      reader = described_class.ask.fmap { |v| called += 1; v * 2 }

      expect(called).to be(0)
      expect(reader.run(3)).to be(6)
      expect(called).to be(1)
    end

    it "accepts a positional callable" do
      expect(described_class.ask.fmap(:to_s).run(7)).to eql("7")
    end

    it "stacks transformations while staying lazy" do
      reader = described_class.ask.fmap { |v| v + 1 }.fmap { |v| v * 10 }

      expect(reader.run(1)).to eql(20)
    end
  end

  describe "#bind" do
    it "threads the environment through both readers" do
      reader =
        Reader { |env| env[:x] }
          .bind { |x| Reader { |env| x + env[:y] } }

      expect(reader.run(x: 2, y: 40)).to eql(42)
    end

    it "does not run the block until #run" do
      called = 0
      reader = described_class.ask.bind do
        called += 1
        described_class.pure(_1)
      end

      expect(called).to be(0)
      reader.run(:env)
      expect(called).to be(1)
    end

    it "raises a TypeError if the block returns a non-Reader" do
      reader = described_class.ask.bind { 1 }

      expect { reader.run(:env) }.to raise_error(TypeError, /must return a Reader/)
    end

    it "supports next inside the block" do
      reader =
        Reader { |env| env[:a] }.bind do |a|
          next described_class.pure(a) if a.even?

          Reader { |env| a + env[:b] }
        end

      expect(reader.run(a: 2, b: 10)).to eql(2)
      expect(reader.run(a: 3, b: 10)).to eql(13)
    end
  end

  describe "#local" do
    it "transforms the environment only for the sub-computation" do
      scoped = described_class.ask.local { |env| env + 100 }

      expect(scoped.run(1)).to eql(101)
    end

    it "does not leak the modified env into surrounding readers" do
      inner = described_class.ask.local { |env| { **env, role: :admin } }
      reader =
        inner.bind do |scoped_env|
          described_class.ask.fmap { |outer_env| [scoped_env, outer_env] }
        end

      outer = { user: "anna" }
      scoped_env, outer_env = reader.run(outer)

      expect(scoped_env).to eql(user: "anna", role: :admin)
      expect(outer_env).to equal(outer)
      expect(outer_env).to eql(user: "anna")
    end

    it "never mutates the external environment" do
      env = { count: 1 }.freeze
      scoped = described_class.ask.local { |e| { **e, count: e[:count] + 10 } }

      expect(scoped.run(env)).to eql(count: 11)
      expect(env).to eql(count: 1)
    end

    it "scopes the transform to the wrapped reader only" do
      scoped = Reader { |env| env[:x] }.local { |env| { **env, x: env[:x] + 100 } }
      reader = scoped.bind do |scoped_x|
        described_class.ask.fmap { |env| [scoped_x, env[:x]] }
      end

      expect(reader.run(x: 1)).to eql([101, 1])
    end

    it "composes nested locals inside-out" do
      nested =
        described_class.ask
                       .local { |env| env + 1 }
                       .local { |env| env * 10 }

      # The inner transform is applied first: (0 * 10) + 1
      expect(nested.run(0)).to eql(1)
      expect(nested.run(2)).to eql(21)
    end

    it "keeps a nested local contained to the inner reader" do
      inner = described_class.ask.fmap { |env| "inner:#{env}" }.local { |env| env + 1 }
      reader = inner.bind do |result|
        described_class.ask.fmap { |env| [result, "outer:#{env}"] }
      end

      expect(reader.run(0)).to eql(["inner:1", "outer:0"])
    end

    it "applies nested transforms outside-in at run time" do
      trace = []
      nested =
        described_class.ask
                       .local { |env| trace << :inner_transform; env + 1 }
                       .local { |env| trace << :outer_transform; env * 10 }

      expect(nested.run(2)).to eql(21)
      expect(trace).to eql(%i[outer_transform inner_transform])
    end
  end

  describe "monad laws on a finite sample" do
    # Small finite sets of environments and values.
    environments = [-3, 0, 7].freeze
    values = [1, 2, 5].freeze

    # Plain functions used by the functor checks.
    functions = {
      identity: ->(v) { v },
      succ: ->(v) { v + 1 },
      double: ->(v) { v * 2 }
    }.freeze

    # Kleisli arrows: value -> Reader.
    arrows = {
      pure: ->(v) { described_class.pure(v) },
      offset: ->(v) { described_class.ask.fmap { |env| v + env } },
      times: ->(v) { described_class.ask.fmap { |env| v * env } }
    }.freeze

    values.each do |value|
      specify "functor identity for #{value.inspect}" do
        reader = described_class.pure(value).fmap(&functions[:identity])

        environments.each do |env|
          expect(reader.run(env)).to eql(described_class.pure(value).run(env))
        end
      end

      arrows.each do |arrow_name, arrow|
        specify "left identity for #{value.inspect} with #{arrow_name}" do
          via_bind = described_class.pure(value).bind(&arrow)

          environments.each do |env|
            expect(via_bind.run(env)).to eql(arrow.(value).run(env))
          end
        end
      end
    end

    arrows.each do |arrow_name, arrow|
      environments.each do |env|
        values.each do |value|
          specify "right identity (#{arrow_name}, env #{env.inspect})" do
            m = arrow.(value)

            expect(m.bind { described_class.pure(_1) }.run(env)).to eql(m.run(env))
          end

          arrows.each do |other_name, other|
            specify "associativity: #{arrow_name} then #{other_name}, env #{env.inspect}" do
              m = arrow.(value)

              left_to_right = m.bind(&arrow).bind(&other)
              nested = m.bind { |v| arrow.(v).bind(&other) }

              expect(left_to_right.run(env)).to eql(nested.run(env))
            end
          end
        end
      end
    end

    it "functor composition agrees with stacked fmap on the sample" do
      environments.each do |env|
        values.each do |value|
          composed =
            described_class.pure(value)
                       .fmap { |v| functions[:double].(functions[:succ].(v)) }
          stacked =
            described_class.pure(value)
                       .fmap(&functions[:succ])
                       .fmap(&functions[:double])

          expect(composed.run(env)).to eql(stacked.run(env))
        end
      end
    end

    specify "local/local composition on the sample" do
      f = ->(env) { env + 1 }
      g = ->(env) { env * 10 }

      environments.each do |env|
        nested = described_class.ask.local(&f).local(&g)
        merged = described_class.ask.local { |e| f.(g.(e)) }

        expect(nested.run(env)).to eql(merged.run(env))
      end
    end
  end

  describe "inspect" do
    it "returns a string" do
      expect(described_class.ask.inspect).to be_a(String)
    end
  end

  describe "mixin" do
    it "exposes the Reader constructor through the mixin" do
      klass = Class.new { include Dry::Monads[:reader] }

      expect(klass.new.Reader { |env| env }.run(:ok)).to be(:ok)
    end
  end
end
