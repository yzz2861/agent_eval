# frozen_string_literal: true

RSpec.describe "Reader" do
  describe "Dry::Monads[:reader] mixin" do
    it "registers Reader and Ask constructors" do
      klass = Class.new { include Dry::Monads[:reader] }
      service = klass.new

      reader = service.Reader { |env| env[:greeting] }
      expect(reader.run(greeting: "hello")).to eql("hello")
      expect(service.Ask { |env| env[:greeting] }.run(greeting: "hi")).to eql("hi")
    end
  end

  # A service whose dependencies (a user repository and a mailer) are
  # passed as a single environment. The service only *describes* the
  # computation: the environment is read when the resulting Reader is
  # executed with #run, not when #call builds it. Each step returns
  # a Result, so the whole computation is a Reader of a Result.
  describe "composing with Result in a service" do
    subject(:service) { Test::NotifyUser.new }

    before do
      stub_const("Test::NotifyUser", Class.new do
        include Dry::Monads[:reader, :result]

        def call(user_id)
          Ask { |env| env[:repo] }.bind do |repo|
            Ask { |env| env[:mailer] }.fmap do |mailer|
              repo.find(user_id).bind { |user| mailer.deliver(user) }
            end
          end
        end
      end)
    end

    let(:repo) do
      Class.new do
        define_method(:find) do |id|
          if id == 1
            Dry::Monads::Success({id: 1, email: "jane@example.com"})
          else
            Dry::Monads::Failure(:not_found)
          end
        end
      end.new
    end

    let(:mailer) do
      Class.new do
        attr_reader :sent

        def initialize = @sent = []

        def deliver(user)
          @sent << user[:email]
          Dry::Monads::Success(:sent)
        end
      end.new
    end

    let(:env) { {repo: repo, mailer: mailer} }

    it "resolves dependencies from the environment and returns a Result" do
      expect(service.call(1).run(env)).to eql(Dry::Monads::Success(:sent))
      expect(service.call(2).run(env)).to eql(Dry::Monads::Failure(:not_found))
      expect(mailer.sent).to eql(["jane@example.com"])
    end

    it "reads the environment at run time, not when the computation is built" do
      computation = service.call(1)

      # The environment is swapped after the computation was built;
      # #run sees the current value, proving the read happens at run time.
      replacement_mailer = mailer.class.new
      env[:mailer] = replacement_mailer

      expect(computation.run(env)).to eql(Dry::Monads::Success(:sent))
      expect(mailer.sent).to be_empty
      expect(replacement_mailer.sent).to eql(["jane@example.com"])
    end

    it "runs the same computation against a different environment" do
      computation = service.call(1)

      other_mailer = mailer.class.new
      other_env = {repo: repo, mailer: other_mailer}

      expect(computation.run(env)).to eql(Dry::Monads::Success(:sent))
      expect(computation.run(other_env)).to eql(Dry::Monads::Success(:sent))
      expect(mailer.sent).to eql(["jane@example.com"])
      expect(other_mailer.sent).to eql(["jane@example.com"])
    end

    it "overrides a dependency for a sub-computation with local" do
      recording_mailer = mailer.class.new

      computation = service.call(1).local { |e| e.merge(mailer: recording_mailer) }

      expect(computation.run(env)).to eql(Dry::Monads::Success(:sent))
      expect(recording_mailer.sent).to eql(["jane@example.com"])
      expect(mailer.sent).to be_empty
      expect(env).to eql(repo: repo, mailer: mailer)
    end
  end
end
