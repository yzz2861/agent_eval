# frozen_string_literal: true

require_relative "helper"

class TestCSVCheckpoint < Test::Unit::TestCase
  def with_csv_file(content)
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write(content)
      file.flush
      yield(file)
    ensure
      file.close
      file.unlink
    end
  end

  def test_checkpoint_is_nil_before_first_record
    csv = CSV.new("a,b\n1,2\n")
    assert_nil(csv.checkpoint)
  end

  def test_checkpoint_is_nil_for_unseekable_input
    ruby = RbConfig.ruby
    IO.popen([ruby, "-e", 'print "a,b\n1,2\n"'], "r") do |io|
      csv = CSV.new(io)
      csv.shift
      assert_nil(csv.checkpoint)
    end
  end

  def test_checkpoint_offsets_are_record_boundaries
    lines = ["h1,h2", "a,1", "b,2", "c,3"]
    csv = CSV.new(lines.join("\n") + "\n", headers: true)
    expected_offset = lines.first.bytesize + 1
    offsets = []
    csv.each_with_index do |_row, index|
      offsets << csv.checkpoint.offset
      expected_offset += lines[index + 1].bytesize + 1
    end
    assert_equal([10, 14, 18], offsets)
    assert_equal(18, expected_offset)
  end

  def test_checkpoint_ignores_parser_read_ahead
    lines = ["h1,h2"] + (1..2000).collect {|i| "name#{i},#{i}"}
    content = lines.join("\n") + "\n"
    with_csv_file(content) do |file|
      csv = CSV.open(file.path, headers: true)
      csv.shift
      checkpoint = csv.checkpoint
      assert_equal("h1,h2\nname1,1\n".bytesize, checkpoint.offset)
      assert_operator(csv.pos, :>, checkpoint.offset + 1000)
      csv.close
    end
  end

  def test_resume_string
    string = "a,b\n1,2\n3,4\n"
    csv = CSV.new(string)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(string, resume: checkpoint)
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_resume_stringio
    stringio = StringIO.new("a,b\n1,2\n3,4\n")
    csv = CSV.new(stringio)
    csv.shift
    checkpoint = csv.checkpoint

    stringio.rewind
    resumed = CSV.new(stringio, resume: checkpoint)
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_resume_restores_headers_and_lineno
    string = "h1,h2\nfoo,0\nbar,1\nbaz,2\n"
    csv = CSV.new(string, headers: true)
    csv.shift
    checkpoint = csv.checkpoint
    assert_equal(["h1", "h2"], checkpoint.headers)
    assert_equal(2, checkpoint.lineno)

    resumed = CSV.new(string, headers: true, resume: checkpoint)
    assert_equal(["h1", "h2"], resumed.headers)
    row = resumed.shift
    assert_equal(CSV::Row.new(["h1", "h2"], ["bar", "1"]), row)
    assert_equal(3, resumed.lineno)
  end

  def test_resume_with_shift
    string = "a,b\n1,2\n3,4\n"
    csv = CSV.new(string)
    csv.shift
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(string, resume: checkpoint)
    assert_equal(["3", "4"], resumed.shift)
    assert_nil(resumed.shift)
  end

  def test_resume_with_dumped_checkpoint
    string = "a,b\n1,2\n3,4\n"
    csv = CSV.new(string)
    csv.shift
    dump = csv.checkpoint.dump

    resumed = CSV.new(string, resume: CSV::Checkpoint.load(dump))
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)

    resumed = CSV.new(string, resume: dump)
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_resume_each_record_boundary
    lines = (1..10).collect {|i| "name#{i},#{i}"}
    content = lines.join("\n") + "\n"
    csv = CSV.new(content)
    checkpoints = []
    csv.each do |_row|
      checkpoints << csv.checkpoint
    end
    checkpoints.each_with_index do |checkpoint, index|
      resumed = CSV.new(content, resume: checkpoint)
      assert_equal(lines[(index + 1)..-1].collect {|line| line.split(",").first},
                   resumed.read.collect(&:first),
                   "resume after record #{index + 1}")
    end
  end

  def test_resume_file
    content = "h1,h2\nfoo,0\nbar,1\n"
    with_csv_file(content) do |file|
      csv = CSV.open(file.path, headers: true)
      csv.shift
      checkpoint = csv.checkpoint
      csv.close

      resumed = CSV.open(file.path, headers: true, resume: checkpoint)
      assert_equal([["bar", "1"]], resumed.read.collect(&:fields))
      resumed.close
    end
  end

  def test_resume_with_foreach
    content = "h1,h2\nfoo,0\nbar,1\n"
    with_csv_file(content) do |file|
      csv = CSV.open(file.path, headers: true)
      csv.shift
      checkpoint = csv.checkpoint
      csv.close

      rows = []
      CSV.foreach(file.path, headers: true, resume: checkpoint) do |row|
        rows << row.fields
      end
      assert_equal([["bar", "1"]], rows)
    end
  end

  def test_resume_with_multiline_quoted_field
    content = +"h1,h2\n"
    content << "\"multi\nline\",1\n"
    content << "plain,2\n"
    csv = CSV.new(content, headers: true)

    first = csv.shift
    assert_equal("multi\nline", first["h1"])
    checkpoint = csv.checkpoint

    resumed = CSV.new(content, headers: true, resume: checkpoint)
    assert_equal([["plain", "2"]], resumed.read.collect(&:fields))

    # A checkpoint taken before the multi-line record must resume in
    # front of it, not inside the quoted field.
    csv = CSV.new(content, headers: true, return_headers: true)
    csv.shift
    checkpoint = csv.checkpoint
    resumed = CSV.new(content, headers: true, return_headers: true,
                      resume: checkpoint)
    row = resumed.shift
    assert_equal("multi\nline", row["h1"])
  end

  def test_resume_keeps_auto_detected_row_separator
    # The quoted "\n" after the checkpoint would fool row separator
    # auto-detection into picking "\n" instead of "\r\n".
    content = +"h1,h2\r\n"
    content << "foo,0\r\n"
    content << "\"quoted\nnewline\",1\r\n"
    content << "bar,2\r\n"
    csv = CSV.new(content, headers: true)
    csv.shift
    checkpoint = csv.checkpoint
    assert_equal("\r\n", checkpoint.row_separator)

    resumed = CSV.new(content, headers: true, resume: checkpoint)
    assert_equal([["quoted\nnewline", "1"], ["bar", "2"]],
                 resumed.read.collect(&:fields))
  end

  def test_resume_with_bom
    content = "\uFEFFh1,h2\nfoo,0\nbar,1\n"
    with_csv_file(content) do |file|
      csv = CSV.open(file.path, "r:bom|utf-8", headers: true)
      first = csv.shift
      checkpoint = csv.checkpoint
      csv.close
      assert_equal(["h1", "h2"], first.headers)
      assert_equal(3 + "h1,h2\nfoo,0\n".bytesize, checkpoint.offset)

      resumed = CSV.open(file.path, "r:bom|utf-8", headers: true,
                           resume: checkpoint)
      assert_equal([["bar", "1"]], resumed.read.collect(&:fields))
      resumed.close
    end
  end

  def test_resume_rejects_changed_file
    content = "h1,h2\nfoo,0\nbar,1\n"
    with_csv_file(content) do |file|
      csv = CSV.open(file.path, headers: true)
      csv.shift
      checkpoint = csv.checkpoint
      csv.close

      file.rewind
      file.truncate(0)
      file.write("h1,h2\nfoo,0\nbar,1\nextra,2\n")
      file.flush

      error = assert_raise(CSV::InvalidCheckpointError) do
        CSV.open(file.path, headers: true, resume: checkpoint)
      end
      assert_match(/input/, error.message)
    end
  end

  def test_resume_rejects_changed_string
    csv = CSV.new("a,b\n1,2\n3,4\n")
    csv.shift
    checkpoint = csv.checkpoint

    assert_raise(CSV::InvalidCheckpointError) do
      CSV.new("a,b\n1,2\n3,X\n", resume: checkpoint)
    end
  end

  def test_resume_rejects_changed_options
    string = "a,b\n1,2\n3,4\n"
    csv = CSV.new(string, headers: true)
    csv.shift
    checkpoint = csv.checkpoint

    error = assert_raise(CSV::InvalidCheckpointError) do
      CSV.new(string, headers: true, col_sep: ";", resume: checkpoint)
    end
    assert_match(/col_sep/, error.message)

    assert_raise(CSV::InvalidCheckpointError) do
      CSV.new(string, resume: checkpoint)
    end
  end

  def test_resume_rejects_malformed_checkpoint
    string = "a,b\n1,2\n3,4\n"
    assert_raise(CSV::InvalidCheckpointError) do
      CSV.new(string, resume: "not a checkpoint")
    end
    assert_raise(CSV::InvalidCheckpointError) do
      CSV.new(string, resume: 42)
    end

    csv = CSV.new(string)
    csv.shift
    hash = csv.checkpoint.to_h
    hash["version"] = 999
    assert_raise(CSV::InvalidCheckpointError) do
      CSV.new(string, resume: hash)
    end
  end

  def test_resume_at_end_of_input
    string = "a,b\n1,2\n"
    csv = CSV.new(string)
    csv.shift
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(string, resume: checkpoint)
    assert_nil(resumed.shift)
  end

  def test_rewind_after_resume
    string = "a,b\n1,2\n3,4\n"
    csv = CSV.new(string)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(string, resume: checkpoint)
    resumed.rewind
    assert_equal([["a", "b"], ["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_batch_import_with_restart
    lines = ["h1,h2"] + (1..100).collect {|i| "name#{i},#{i}"}
    content = lines.join("\n") + "\n"

    imported = []
    checkpoint_dump = nil
    csv = CSV.new(content, headers: true)
    csv.each do |row|
      imported << row.fields
      checkpoint_dump = csv.checkpoint.dump
      break if imported.size == 40
    end

    # Simulate a restart: a new CSV over the same input, resumed from the
    # persisted checkpoint, continues with the next unparsed record.
    resumed = CSV.new(content, headers: true, resume: checkpoint_dump)
    resumed.each do |row|
      imported << row.fields
    end

    assert_equal((1..100).collect {|i| ["name#{i}", "#{i}"]}, imported)
  end
end
