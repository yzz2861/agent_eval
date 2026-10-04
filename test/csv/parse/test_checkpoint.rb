# frozen_string_literal: true

require_relative "../helper"

class TestCSVParseCheckpoint < Test::Unit::TestCase
  def test_checkpoint_and_resume_stringio
    data = "a,b,c\n1,2,3\n4,5,6\n7,8,9\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(data, headers: true)
    resumed.resume(checkpoint)
    assert_equal([{"a" => "4", "b" => "5", "c" => "6"},
                  {"a" => "7", "b" => "8", "c" => "9"}],
                 resumed.read.map(&:to_h))
  end

  def test_checkpoint_position_is_not_io_pos
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write("a,b\n1,2\n3,4\n")
      file.flush
      csv = CSV.open(file.path)
      csv.shift
      checkpoint = csv.checkpoint
      # The parser read the whole (small) file in one chunk, so the IO
      # position is at the end of the file while the checkpoint points
      # at the start of the second record.
      assert_equal(4, checkpoint.position)
      assert_operator(csv.pos, :>, checkpoint.position)
      csv.close
    ensure
      file.close!
    end
  end

  def test_batch_import_scenario
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write("name,value\n")
      10.times {|i| file.write("row#{i},#{i}\n") }
      file.flush
      path = file.path

      checkpoint_dump = nil
      imported = []
      csv = CSV.open(path, headers: true)
      csv.each_slice(3) do |batch|
        imported.concat(batch.map {|row| row["name"] })
        checkpoint_dump = csv.checkpoint.dump
        break # simulate a crash after the first batch
      end
      csv.close
      assert_equal(%w[row0 row1 row2], imported)

      resumed = CSV.open(path, headers: true)
      resumed.resume(CSV::Checkpoint.load(checkpoint_dump))
      assert_equal(%w[row3 row4 row5 row6 row7 row8 row9],
                   resumed.read.map {|row| row["name"] })
      resumed.close
    ensure
      file.close!
    end
  end

  def test_bom
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write("\uFEFFname,value\nfoo,1\nbar,2\nbaz,3\n")
      file.flush
      csv = CSV.open(file.path, encoding: "bom|utf-8", headers: true)
      assert_equal({"name" => "foo", "value" => "1"}, csv.shift.to_h)
      checkpoint = csv.checkpoint
      csv.close

      resumed = CSV.open(file.path, encoding: "bom|utf-8", headers: true)
      resumed.resume(checkpoint)
      assert_equal([{"name" => "bar", "value" => "2"},
                    {"name" => "baz", "value" => "3"}],
                   resumed.read.map(&:to_h))
      resumed.close
    ensure
      file.close!
    end
  end

  def test_multiline_quoted_fields
    data = "id,text\n" +
           "1,\"line1\nline2\"\n" +
           "2,\"line3\nline4\nline5\"\n" +
           "3,simple\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(data, headers: true)
    resumed.resume(checkpoint)
    assert_equal([{"id" => "2", "text" => "line3\nline4\nline5"},
                  {"id" => "3", "text" => "simple"}],
                 resumed.read.map(&:to_h))
  end

  def test_multiline_quoted_fields_in_file
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write("id,text\n1,\"line1\nline2\"\n2,\"line3\nline4\"\n")
      file.flush
      csv = CSV.open(file.path, headers: true)
      csv.shift
      checkpoint = csv.checkpoint
      csv.close

      resumed = CSV.open(file.path, headers: true)
      resumed.resume(checkpoint)
      assert_equal([{"id" => "2", "text" => "line3\nline4"}],
                   resumed.read.map(&:to_h))
      resumed.close
    ensure
      file.close!
    end
  end

  def test_auto_row_separator_crlf
    data = "a,b\r\n1,2\r\n3,4\r\n"
    csv = CSV.new(data)
    csv.shift
    checkpoint = csv.checkpoint
    assert_equal("\r\n", checkpoint.options["row_separator"])

    resumed = CSV.new(data)
    resumed.resume(checkpoint)
    assert_equal("\r\n", resumed.row_sep)
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_auto_row_separator_cr
    data = "a,b\r1,2\r3,4\r"
    csv = CSV.new(data)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(data)
    resumed.resume(checkpoint)
    assert_equal("\r", resumed.row_sep)
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_headers_not_reread_nor_reemitted
    data = "a,b\n1,2\n3,4\n"
    csv = CSV.new(data, headers: true, return_headers: true)
    header_row = csv.shift
    assert_predicate(header_row, :header_row?)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(data, headers: true, return_headers: true)
    resumed.resume(checkpoint)
    assert_equal(%w[a b], resumed.headers)
    assert_equal([["3", "4"]], resumed.read.map(&:fields))
  end

  def test_headers_available_after_resume
    data = "a,b\n1,2\n3,4\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(data, headers: true)
    resumed.resume(checkpoint)
    assert_equal(%w[a b], resumed.headers)
    row = resumed.shift
    assert_equal("3", row["a"])
    assert_equal("4", row["b"])
  end

  def test_checkpoint_before_any_read
    data = "a,b\n1,2\n"
    csv = CSV.new(data, headers: true)
    checkpoint = csv.checkpoint
    assert_equal(0, checkpoint.position)

    resumed = CSV.new(data, headers: true)
    resumed.resume(checkpoint)
    assert_equal([{"a" => "1", "b" => "2"}], resumed.read.map(&:to_h))
  end

  def test_checkpoint_at_eof
    data = "a,b\n1,2\n"
    csv = CSV.new(data)
    csv.read
    checkpoint = csv.checkpoint

    resumed = CSV.new(data)
    resumed.resume(checkpoint)
    assert_equal([], resumed.read)
  end

  def test_chained_checkpoints
    data = "1\n2\n3\n4\n5\n"
    csv = CSV.new(data)
    csv.shift
    checkpoint1 = csv.checkpoint

    csv2 = CSV.new(data)
    csv2.resume(checkpoint1)
    assert_equal(["2"], csv2.shift)
    checkpoint2 = csv2.checkpoint

    csv3 = CSV.new(data)
    csv3.resume(checkpoint2)
    assert_equal([["3"], ["4"], ["5"]], csv3.read)
  end

  def test_lineno_continues_after_resume
    data = "a,b\n1,2\n3,4\n5,6\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    csv.shift
    checkpoint = csv.checkpoint
    assert_equal(3, checkpoint.lineno)

    resumed = CSV.new(data, headers: true)
    resumed.resume(checkpoint)
    assert_equal(3, resumed.lineno)
    resumed.shift
    assert_equal(4, resumed.lineno)
  end

  def test_options_mismatch_rejected
    data = "a,b\n1,2\n"
    csv = CSV.new(data)
    csv.shift
    checkpoint = csv.checkpoint

    assert_raise(CSV::CheckpointError) do
      CSV.new(data, col_sep: ";").resume(checkpoint)
    end
    assert_raise(CSV::CheckpointError) do
      CSV.new(data, quote_char: "'").resume(checkpoint)
    end
    assert_raise(CSV::CheckpointError) do
      CSV.new(data, skip_blanks: true).resume(checkpoint)
    end
    assert_raise(CSV::CheckpointError) do
      CSV.new(data, headers: true).resume(checkpoint)
    end
  end

  def test_input_changed_rejected
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write("a,b\n1,2\n3,4\n")
      file.flush
      csv = CSV.open(file.path)
      csv.shift
      checkpoint = csv.checkpoint
      csv.close

      File.write(file.path, "a,b\n1,2\n3,4\n5,6\n")
      assert_raise(CSV::CheckpointError) do
        CSV.open(file.path) {|resumed| resumed.resume(checkpoint) }
      end
    ensure
      file.close!
    end
  end

  def test_other_input_rejected
    file = Tempfile.new(["checkpoint", ".csv"])
    other = Tempfile.new(["checkpoint-other", ".csv"])
    begin
      file.write("a,b\n1,2\n")
      file.flush
      other.write("a,b\n1,2\n")
      other.flush
      csv = CSV.open(file.path)
      csv.shift
      checkpoint = csv.checkpoint
      csv.close

      assert_raise(CSV::CheckpointError) do
        CSV.open(other.path) {|resumed| resumed.resume(checkpoint) }
      end
    ensure
      file.close!
      other.close!
    end
  end

  def test_stringio_content_change_rejected
    csv = CSV.new("a,b\n1,2\n3,4\n")
    csv.shift
    checkpoint = csv.checkpoint

    assert_raise(CSV::CheckpointError) do
      CSV.new("a,b\n1,2\n9,9\n").resume(checkpoint)
    end
  end

  def test_non_seekable_input_rejected
    reader, writer = IO.pipe
    begin
      writer.write("a,b\n1,2\n")
      writer.close
      csv = CSV.new(reader)
      csv.shift
      assert_raise(CSV::CheckpointError) do
        csv.checkpoint
      end
    ensure
      reader.close
    end
  end

  def test_transcoding_input_rejected
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      file.write("a,b\n1,2\n")
      file.flush
      io = File.open(file.path, "r:utf-8:utf-16le")
      csv = CSV.new(io)
      assert_raise(CSV::CheckpointError) do
        csv.checkpoint
      end
      io.close
    ensure
      file.close!
    end
  end

  def test_checkpoint_roundtrip
    data = "a,b\n1,2\n3,4\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    checkpoint = csv.checkpoint

    from_h = CSV::Checkpoint.from_h(checkpoint.to_h)
    resumed = CSV.new(data, headers: true)
    resumed.resume(from_h)
    assert_equal([["3", "4"]], resumed.read.map(&:fields))

    from_dump = CSV::Checkpoint.load(checkpoint.dump)
    resumed = CSV.new(data, headers: true)
    resumed.resume(from_dump)
    assert_equal([["3", "4"]], resumed.read.map(&:fields))
  end

  def test_checkpoint_roundtrip_json
    require "json"
    data = "a,b\n1,2\n3,4\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    checkpoint = csv.checkpoint

    restored = CSV::Checkpoint.from_h(JSON.parse(JSON.generate(checkpoint.to_h)))
    resumed = CSV.new(data, headers: true)
    resumed.resume(restored)
    assert_equal([["3", "4"]], resumed.read.map(&:fields))
  end

  def test_unsupported_checkpoint_version_rejected
    hash = CSV.new("a\n1\n").checkpoint.to_h
    hash["version"] = -1
    assert_raise(CSV::CheckpointError) do
      CSV::Checkpoint.from_h(hash)
    end
  end

  def test_checkpoint_not_at_record_boundary
    data = "a,b\n\"unclosed\n1,2\n"
    csv = CSV.new(data)
    csv.shift
    assert_raise(CSV::MalformedCSVError) do
      csv.shift
    end
    error = assert_raise(CSV::CheckpointError) do
      csv.checkpoint
    end
    assert_match(/complete record/, error.message)
  end

  def test_large_file_across_chunks
    file = Tempfile.new(["checkpoint", ".csv"])
    begin
      rows = 500.times.map {|i| "row#{i},#{"x" * 40}#{i}" }
      file.write(rows.join("\n"))
      file.write("\n")
      file.flush
      # The file is larger than the parser chunk size, so parsing spans
      # multiple chunks.
      assert_operator(File.size(file.path), :>, 8192)

      csv = CSV.open(file.path)
      checkpoint = nil
      csv.each_slice(100) do |_batch|
        checkpoint = csv.checkpoint
        break
      end
      csv.close

      resumed = CSV.open(file.path)
      resumed.resume(checkpoint)
      assert_equal(rows[100..-1].map {|line| line.split(",") },
                   resumed.read)
      resumed.close
    ensure
      file.close!
    end
  end

  def test_skip_lines
    data = "# comment\na,b\n1,2\n3,4\n"
    options = {skip_lines: /\A#/}
    csv = CSV.new(data, **options)
    csv.shift
    checkpoint = csv.checkpoint

    resumed = CSV.new(data, **options)
    resumed.resume(checkpoint)
    assert_equal([["1", "2"], ["3", "4"]], resumed.read)
  end

  def test_rewind_after_resume
    data = "a,b\n1,2\n3,4\n"
    csv = CSV.new(data, headers: true)
    csv.shift
    checkpoint = csv.checkpoint
    csv.resume(checkpoint)
    assert_equal([{"a" => "3", "b" => "4"}], csv.read.map(&:to_h))

    csv.rewind
    assert_equal([{"a" => "1", "b" => "2"}, {"a" => "3", "b" => "4"}],
                 csv.read.map(&:to_h))
  end

  def test_resume_returns_self
    csv = CSV.new("a\n1\n")
    checkpoint = csv.checkpoint
    assert_same(csv, csv.resume(checkpoint))
  end
end
