require File.dirname(__FILE__) + "/../spec_helper"

module IceCube
  describe HashParser do
    let(:t) { Time.utc(2014, 3, 22) }

    describe "#to_schedule" do
      subject(:schedule) { HashParser.new(hash).to_schedule }

      let(:hash) { {start_time: t, duration: 3600} }

      describe "#start_time" do
        subject { super().start_time }
        it { is_expected.to eq(t) }
      end

      describe "#duration" do
        subject { super().duration }
        it { is_expected.to eq(3600) }
      end

      describe "end_time overrules duration" do
        let(:hash) { {start_time: t, end_time: t + 1800, duration: 3600} }

        describe "#duration" do
          subject { super().duration }
          it { is_expected.to eq(1800) }
        end
      end

      describe "additional occurrence periods" do
        it "round-trips a period by start and end time" do
          extra_start = t + ONE_DAY
          extra_end = extra_start + 900
          schedule = described_class.new(
            start_time: t,
            duration: 3600,
            rtimes: [{start_time: extra_start, end_time: extra_end}]
          ).to_schedule

          expect(schedule.first(2).last.end_time).to eq(extra_end)

          restored = IceCube::Schedule.from_hash(schedule.to_hash)
          expect(restored.rtimes.first).to eq(extra_start)
          expect(restored.rtimes.first.end_time).to eq(extra_end)
        end

        it "accepts a period by start time and duration" do
          extra_start = t + ONE_DAY
          schedule = described_class.new(
            start_time: t,
            rtimes: [{time: extra_start, duration: 900}]
          ).to_schedule

          expect(schedule.rtimes.first.end_time).to eq(extra_start + 900)
        end
      end
    end
  end
end
