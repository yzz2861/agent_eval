# frozen_string_literal: true

RSpec.describe(Dry::Monads::Reader) do
  mixin = Dry::Monads::Reader::Mixin
  include mixin

  subject(:reader) { Reader { |env| env[:count] * 2 } }

  it_behaves_like "a monad"

  describe "#run" do
    it "reads the environment at run time, not when the computation is built" do
      env = {count: 1}
      m = Reader { |e| e[:count] }

      env[:count] = 2

      expect(m.run(env)).to be(2)
    end

    it "runs the same computation with different environments" do
      expect(reader.run(count: 2)).to be(4)
      expect(reader.run(count: 5)).to be(10)
    end

    it "runs the same computation repeatedly" do
      expect(2.times.map { reader.run(count: 3) }).to eql([6, 6])
    end
  end

  describe ".pure" do
    it "ignores the environment" do
      expect(described_class.pure(42).run({})).to be(42)
    end

    it "wraps a block, mirroring Result.pure" do
      block = -> { 42 }
      expect(described_class.pure(&block).run(nil)).to be(block)
    end
  end

  describe ".ask" do
    it "returns the whole environment" do
      env = {repo: :fake}
      expect(described_class.ask.run(env)).to be(env)
    end

    it "returns a selected part of the environment" do
      ask_repo = described_class.ask(-> env { env[:repo] })
      expect(ask_repo.run(repo: :fake)).to be(:fake)
    end
  end

  describe "Ask constructor" do
    it "returns the whole environment without arguments" do
      expect(Ask().run(:env)).to be(:env)
    end

    it "accepts a selector as a block" do
      expect(Ask { |env| env[:key] }.run(key: 1)).to be(1)
    end
  end

  describe "#fmap" do
    it "transforms the result within the same environment" do
      expect(reader.fmap { _1 + 1 }.run(count: 2)).to be(5)
    end

    it "delays evaluation until #run" do
      eff = 0
      m = reader.fmap { eff += 1 }
      expect(eff).to be(0)
      m.run(count: 1)
      expect(eff).to be(1)
    end
  end

  describe "#bind" do
    it "threads the environment through both computations" do
      m = Ask { |env| env[:base] }.bind { |base|
        Ask { |env| base + env[:offset] }
      }

      expect(m.run(base: 10, offset: 5)).to be(15)
    end
  end

  describe "#local" do
    it "scopes the modified environment to the sub-computation" do
      m = Ask { |env| env[:lang] }.local { |env| env.merge(lang: :fr) }
      sibling = Ask { |env| env[:lang] }

      expect(m.run(lang: :en)).to be(:fr)
      expect(sibling.run(lang: :en)).to be(:en)
    end

    it "does not mutate the outer environment object" do
      env = {lang: :en, nested: {level: 1}}
      m = Ask().local { |e| e.merge(lang: :fr) }

      m.run(env)

      expect(env).to eql(lang: :en, nested: {level: 1})
    end

    it "restores the outer environment after nested locals" do
      m = Ask { |env| env[:lang] }.local { |env| env.merge(lang: :fr) }.bind { |fr|
        Ask().local { |env| env.merge(lang: :de) }.bind { |de_env|
          Ask { |env| env[:lang] }.fmap { |restored| [fr, de_env[:lang], restored] }
        }
      }

      expect(m.run(lang: :en)).to eql(%i[fr de en])
    end
  end

  describe "exceptions" do
    it "propagates them instead of converting to a Failure" do
      m = Reader { raise "boom" }

      expect { m.run({}) }.to raise_error(RuntimeError, "boom")
    end

    it "propagates exceptions raised inside fmap/bind" do
      expect { described_class.pure(1).fmap { raise "boom" }.run(nil) }
        .to raise_error(RuntimeError, "boom")
      expect { described_class.pure(1).bind { raise "boom" }.run(nil) }
        .to raise_error(RuntimeError, "boom")
    end
  end

  describe "monad laws" do
    # Laws are checked extensionally over a finite sample of environments:
    # two Readers are considered equal when they agree on every sample.
    environments = [
      {},
      {n: 0},
      {n: 1},
      {n: 7, extra: :ignored}
    ].freeze

    let(:m) { Reader { |env| env.fetch(:n, 0) } }
    let(:f) { -> n { Reader { |env| n + env.fetch(:n, 0) } } }
    let(:g) { -> n { described_class.pure(n * 2) } }

    def results(reader, environments)
      environments.map { |env| reader.run(env) }
    end

    it "satisfies left identity: pure(a).bind(f) == f(a)" do
      [0, 3].each do |a|
        left = described_class.pure(a).bind(&f)
        right = f.(a)

        expect(results(left, environments)).to eql(results(right, environments))
      end
    end

    it "satisfies right identity: m.bind(pure) == m" do
      bound = m.bind { |value| described_class.pure(value) }

      expect(results(bound, environments)).to eql(results(m, environments))
    end

    it "satisfies associativity: (m.bind(f)).bind(g) == m.bind { |x| f(x).bind(g) }" do
      left = m.bind(&f).bind(&g)
      right = m.bind { |x| f.(x).bind(&g) }

      expect(results(left, environments)).to eql(results(right, environments))
    end
  end
end
