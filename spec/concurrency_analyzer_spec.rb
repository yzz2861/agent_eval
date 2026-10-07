#
# Specifying rufus-scheduler concurrency analysis
#

require 'spec_helper'

describe Rufus::Scheduler do

  before :each do
    @scheduler = Rufus::Scheduler.new
  end
  after :each do
    @scheduler.shutdown
  end

  def result(durations={}, options={})

    @scheduler.analyze_concurrency(
      @from, @to, durations, options
    )
  end

  it 'scans hand-computed every and interval overlaps' do

    @from = zutc(2030, 1, 1, 10, 0, 0)
    @to = zutc(2030, 1, 1, 10, 0, 15)

    every_job =
      @scheduler.schedule_every(
        '10s', first_at: @from
      ) {}
    interval_job =
      @scheduler.schedule_interval(
        '3s', first_at: @from
      ) {}

    next_times = [ every_job.next_time.to_f, interval_job.next_time.to_f ]

    report = result(every: 6, interval: 2)
    windows = report[:peak_windows]

    expect(report[:peak_concurrency]).to eq(2)
    expect(report[:complete]).to eq(true)
    expect(windows.size).to eq(3)
    expect(windows.collect { |window| window[:start_time].to_f }).to eq(
      [ @from.to_f, (@from + 5).to_f, (@from + 10).to_f ]
    )
    expect(windows.collect { |window| window[:end_time].to_f }).to eq(
      [ (@from + 2).to_f, (@from + 6).to_f, (@from + 12).to_f ]
    )
    expect(windows.collect { |window| window[:duration] }).to eq([ 2, 1, 2 ])
    expect(windows.all? { |window|
      window[:jobs] == [ every_job, interval_job ]
    }).to eq(true)
    expect([ every_job.next_time.to_f, interval_job.next_time.to_f ]).to eq(next_times)
  end

  it 'uses cron zones when intersecting runs' do

    @from = zutc(2030, 1, 1, 10, 0, 0)
    @to = zutc(2030, 1, 1, 10, 1, 0)

    tokyo_job =
      @scheduler.schedule_cron(
        '0 19 * * * Asia/Tokyo'
      ) {}
    chicago_job =
      @scheduler.schedule_cron(
        '0 4 * * * America/Chicago'
      ) {}

    report = result(tokyo_job => 30, chicago_job => 45)
    window = report[:peak_windows].first

    expect(report[:peak_concurrency]).to eq(2)
    expect(window[:start_time].to_f).to eq(@from.to_f)
    expect(window[:end_time].to_f).to eq((@from + 30).to_f)
    expect(window[:jobs].sort_by(&:id)).to eq(
      [ chicago_job, tokyo_job ].sort_by(&:id)
    )
  end

  it 'treats zero durations and touching half-open runs as non-overlapping' do

    @from = zutc(2030, 1, 1, 10, 0, 0)
    @to = zutc(2030, 1, 1, 10, 0, 10)

    long_every_job =
      @scheduler.schedule_every(
        '10s', first_at: @from
      ) {}
    touching_every_job =
      @scheduler.schedule_every(
        '10s', first_at: @from + 5
      ) {}
    zero_every_job =
      @scheduler.schedule_every(
        '10s', first_at: @from
      ) {}

    report =
      result(
        long_every_job => 5,
        touching_every_job => 5,
        zero_every_job => 0
      )
    windows = report[:peak_windows]

    expect(report[:peak_concurrency]).to eq(1)
    expect(windows.size).to eq(2)
    expect(windows.collect { |window| window[:start_time].to_f }).to eq(
      [ @from.to_f, (@from + 5).to_f ]
    )
    expect(windows.collect { |window| window[:end_time].to_f }).to eq(
      [ (@from + 5).to_f, @to.to_f ]
    )
    expect(windows.collect { |window| window[:jobs] }).to eq(
      [ [ long_every_job ], [ touching_every_job ] ]
    )
  end

  it 'reports an incomplete analysis when the expansion limit is reached' do

    @from = zutc(2030, 1, 1, 10, 0, 0)
    @to = zutc(2030, 1, 1, 10, 1, 0)

    job_a =
      @scheduler.schedule_every(
        '1s', first_at: @from
      ) {}
    job_b =
      @scheduler.schedule_every(
        '1s', first_at: @from
      ) {}

    next_times = [ job_a.next_time.to_f, job_b.next_time.to_f ]

    report = result(0, max_expansions: 3)

    expect(report[:complete]).to eq(false)
    expect(report[:truncated_jobs].sort_by(&:id)).to eq(
      [ job_a, job_b ].sort_by(&:id)
    )
    expect(report[:peak_concurrency]).to eq(0)
    expect(report[:peak_windows]).to eq([])
    expect([ job_a.next_time.to_f, job_b.next_time.to_f ]).to eq(next_times)
  end
end
