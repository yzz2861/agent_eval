require "open3"
require "rbconfig"

RSpec.describe Flipper::Adapters::Memory do
  let(:source) { {} }

  context 'threadsafe: true' do
    subject { described_class.new(source, threadsafe: true) }

    it_should_behave_like 'a flipper adapter'
  end

  context 'threadsafe: false' do
    subject { described_class.new(source, threadsafe: false) }

    it_should_behave_like 'a flipper adapter'
  end

  it "can initialize from big hash" do
    flipper = Flipper.new(subject)
    flipper.enable :subscriptions
    flipper.disable :search
    flipper.enable_percentage_of_actors :pro_deal, 20
    flipper.enable_percentage_of_time :logging, 30
    flipper.enable_actor :following, Flipper::Actor.new('1')
    flipper.enable_actor :following, Flipper::Actor.new('3')
    flipper.enable_group :following, Flipper::Types::Group.new(:staff)

    dup = described_class.new(subject.get_all)

    expect(dup.get_all).to eq({
      "subscriptions" => subject.default_config.merge(boolean: "true"),
      "search" => subject.default_config,
      "logging" => subject.default_config.merge(:percentage_of_time => "30"),
      "pro_deal" => subject.default_config.merge(:percentage_of_actors => "20"),
      "following" => subject.default_config.merge(actors: Set["1", "3"], groups: Set["staff"]),
    })
  end

  describe '#supports_evaluation_snapshots?' do
    it 'supports strong evaluation snapshots' do
      expect(subject).to be_supports_evaluation_snapshots
    end
  end

  describe '#evaluation_snapshot' do
    it 'returns a deeply frozen copy of the current configuration' do
      flipper = Flipper.new(subject)
      flipper.enable_expression(:search, Flipper.property(:plan).eq('basic'))
      flipper.enable_actor(:search, Flipper::Actor.new('1'))

      snapshot = subject.evaluation_snapshot
      values = snapshot.get_all['search']

      expect(snapshot.read_only?).to be(true)
      expect(values).to be_frozen
      expect(values[:actors]).to be_frozen
      expect(values[:expression]).to be_frozen
      expect(values).not_to equal(subject.get(flipper[:search]))
    end

    it 'rejects unsupported consistency levels' do
      expect {
        subject.evaluation_snapshot(consistency: :eventual)
      }.to raise_error(ArgumentError, 'unsupported consistency: :eventual')
    end

    it 'is read-only' do
      flipper = Flipper.new(subject)
      snapshot = subject.evaluation_snapshot

      expect {
        snapshot.add(flipper[:search])
      }.to raise_error(Flipper::Adapters::EvaluationSnapshotReadOnly, 'evaluation snapshots are read-only')
    end
  end

  describe '#with_evaluation_snapshot' do
    it 'restores live reads after an exception' do
      subject.add(Flipper::Feature.new(:search, subject))

      expect {
        subject.with_evaluation_snapshot { raise 'boom' }
      }.to raise_error('boom')

      expect(subject.current_evaluation_snapshot).to be_nil
    end

    it 'scopes snapshots per thread' do
      subject.add(Flipper::Feature.new(:search, subject))
      snapshot = subject.evaluation_snapshot
      queue = Queue.new

      thread = Thread.new do
        subject.with_evaluation_snapshot do
          queue << subject.current_evaluation_snapshot.object_id
          sleep 0.05
        end
      end

      nested_id = queue.pop
      expect(subject.current_evaluation_snapshot).to be_nil
      expect(nested_id).not_to eq(snapshot.object_id)
      thread.join
    end
  end

  it "uses its inherited Mutex safely after a fork" do
    skip "Process.fork is not supported" unless Process.respond_to?(:fork)

    script = <<~'RUBY'
      require "flipper"

      adapter = Flipper::Adapters::Memory.new({}, threadsafe: true)
      mutex = adapter.instance_variable_get(:@lock)
      raise "memory adapter does not use Mutex" unless mutex.instance_of?(Mutex)

      locked = Queue.new
      release = Queue.new
      holder = Thread.new do
        mutex.lock
        locked << true
        release.pop
        mutex.unlock
      end
      locked.pop

      begin
        child_pid = fork do
          begin
            adapter.features
            exit! 0
          rescue => error
            warn error.message
            exit! 1
          end
        end

        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
        status = nil
        until status
          if result = Process.wait2(child_pid, Process::WNOHANG)
            _, status = result
          elsif Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
            Process.kill("KILL", child_pid)
            Process.wait(child_pid)
            raise "forked child timed out"
          else
            sleep 0.01
          end
        end
      ensure
        release << true
        holder.join(1)
      end

      exit(status.success? ? 0 : 1)
    RUBY

    _, stderr, status = Open3.capture3(
      RbConfig.ruby,
      "-Ilib",
      "-e",
      script,
      chdir: File.expand_path("../../..", __dir__)
    )

    expect(status).to be_success, stderr
  end
end
