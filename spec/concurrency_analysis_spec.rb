
#
# Specifying rufus-scheduler
#

require 'spec_helper'


describe Rufus::Scheduler::ConcurrencyAnalysis do

  before :each do
    @scheduler = Rufus::Scheduler.new
    @t0 = Time.utc(2030, 1, 1, 0, 0, 0)
  end
  after :each do
    @scheduler.shutdown
  end

  def zt(offset)

    EtOrbi::EoTime.new((@t0 + offset).to_f, 'Zulu')
  end

  def windows(a)

    a.peak_windows.collect { |w|
      [
        (w.starts_at.to_f - @t0.to_f).round(3),
        (w.ends_at.to_f - @t0.to_f).round(3)
      ]
    }
  end

  it 'computes the peak for interleaved every and interval jobs' do

    ja = @scheduler.every('10s', tag: 'a', job: true) {}
    jb = @scheduler.interval('5s', tag: 'b', job: true) {}

    ja.next_time = zt(10)
    jb.next_time = zt(12)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 60,
      { 'a' => 25, 'b' => 10 })

    # job a (every 10s, 25s of work):
    #   [10,35) [20,45) [30,55) [40,65) [50,75)
    # job b (interval 5s after 10s of work):
    #   [12,22) [27,37) [42,52) [57,67)

    expect(a.complete?).to eq(true)
    expect(a.peak).to eq(4)
    expect(windows(a)).to eq([
      [ 30.0, 35.0 ], [ 42.0, 45.0 ], [ 50.0, 52.0 ]
    ])
    expect(a.contributors).to match_array([ ja, jb ])
  end

  it 'counts interval jobs from the estimated end of the previous run' do

    ji = @scheduler.interval('5s', tag: 'i', job: true) {}
    ji.next_time = zt(0)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 70, { 'i' => 20 })

    # 20s of work + 5s interval: starts at 0, 25, 50
    # (not every 5s), so the job never overlaps itself

    expect(a.peak).to eq(1)
    expect(windows(a)).to eq([
      [ 0.0, 20.0 ], [ 25.0, 45.0 ], [ 50.0, 70.0 ]
    ])
  end

  it 'treats intervals as half-open (end == start does not overlap)' do

    ja = @scheduler.every('20s', tag: 'a', job: true) {}
    jb = @scheduler.every('20s', tag: 'b', job: true) {}

    ja.next_time = zt(10)
    jb.next_time = zt(20)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 60,
      { 'a' => 10, 'b' => 10 })

    # [10,20) [30,40) [50,60) and [20,30) [40,50):
    # perfectly interleaved, never overlapping

    expect(a.peak).to eq(1)
    expect(windows(a)).to eq([ [ 10.0, 60.0 ] ])
    expect(a.contributors).to match_array([ ja, jb ])
  end

  it 'ignores zero duration jobs' do

    ja = @scheduler.every('10s', tag: 'a', job: true) {}
    jb = @scheduler.every('20s', tag: 'b', job: true) {}

    ja.next_time = zt(10)
    jb.next_time = zt(10)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 60,
      { 'a' => 0, 'b' => 10 })

    expect(a.peak).to eq(1)
    expect(a.contributors).to eq([ jb ])
  end

  it 'returns a zero peak when no job is scheduled' do

    a = @scheduler.concurrency_analysis(@t0, @t0 + 60, {})

    expect(a.complete?).to eq(true)
    expect(a.peak).to eq(0)
    expect(a.peak_windows).to eq([])
    expect(a.contributors).to eq([])
  end

  it 'aligns cron occurrences across time zones' do

    ja = @scheduler.cron('0 8 * * * Asia/Shanghai', tag: 'a', job: true) {}
    jb = @scheduler.cron('0 0 * * * UTC', tag: 'b', job: true) {}

    ja.next_time = zt(2 * 86_400) # 2030-01-03 00:00:00 UTC
    jb.next_time = zt(2 * 86_400)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 4 * 86_400,
      { 'a' => 600, 'b' => 600 })

    # 08:00 in Shanghai is 00:00 UTC: both jobs fire at the same
    # instant each UTC day and overlap for 600s

    expect(a.complete?).to eq(true)
    expect(a.peak).to eq(2)
    expect(windows(a)).to eq([
      [ 2 * 86_400.0, 2 * 86_400.0 + 600 ],
      [ 3 * 86_400.0, 3 * 86_400.0 + 600 ]
    ])
    expect(a.contributors).to match_array([ ja, jb ])
  end

  it 'reports an incomplete analysis when the expansion limit is hit' do

    ja = @scheduler.every('1s', tag: 'a', job: true) {}
    ja.next_time = zt(1)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 100,
      { 'a' => 5 },
      max_expansions: 10)

    expect(a.complete?).to eq(false)
    expect(a.expansions).to eq(10)

    # the 11th occurrence (at t0 + 11) could not be expanded,
    # so the result only covers [ t0, t0 + 11 )

    expect(a.covered_until.to_f).to eq((@t0 + 11).to_f)

    # over the covered window: [1,6) [2,7) ... [10,15),
    # five of them overlap from t0 + 10 on

    expect(a.peak).to eq(5)
  end

  it 'does not modify the jobs or their next times' do

    ja = @scheduler.every('5s', times: 100, tag: 'a', job: true) {}
    jb = @scheduler.interval('7s', tag: 'b', job: true) {}

    nta = ja.next_time
    ntb = jb.next_time

    @scheduler.concurrency_analysis(
      Time.now, Time.now + 3600,
      { 'a' => 2, 'b' => 3 })

    expect(ja.next_time).to eq(nta)
    expect(jb.next_time).to eq(ntb)
    expect(ja.times).to eq(100)
    expect(ja.count).to eq(0)
    expect(jb.count).to eq(0)
  end

  it 'accepts a callable and a :default for the durations' do

    ja = @scheduler.every('20s', tag: 'a', job: true) {}
    jb = @scheduler.every('20s', tag: 'b', job: true) {}

    ja.next_time = zt(10)
    jb.next_time = zt(15)

    a = @scheduler.concurrency_analysis(
      @t0, @t0 + 60,
      lambda { |job| job.tags.include?('a') ? 10 : 0 })

    expect(a.peak).to eq(1)
    expect(a.contributors).to eq([ ja ])

    b = @scheduler.concurrency_analysis(
      @t0, @t0 + 60,
      { :default => 10 })

    # [10,20) [30,40) [50,60) and [15,25) [35,45) [55,65)

    expect(b.peak).to eq(2)
    expect(windows(b)).to eq([
      [ 15.0, 20.0 ], [ 35.0, 40.0 ], [ 55.0, 60.0 ]
    ])
  end

  it 'fails on negative durations' do

    ja = @scheduler.every('10s', tag: 'a', job: true) {}
    ja.next_time = zt(10)

    expect {
      @scheduler.concurrency_analysis(@t0, @t0 + 60, { 'a' => -1 })
    }.to raise_error(ArgumentError, /negative duration/)
  end

  it 'fails when the window is empty or inverted' do

    expect {
      @scheduler.concurrency_analysis(@t0, @t0, {})
    }.to raise_error(ArgumentError, /must be after/)
  end
end
