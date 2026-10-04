require "test_helper"
require "shrine/plugins/resumable_uploads"

describe Shrine::ResumableUpload::Session do
  it "merges adjacent and overlapping ranges" do
    session = Shrine::ResumableUpload::Session.new(
      total_size: 20,
      ranges: [[0, 5], [10, 15], [5, 10], [15, 20]],
    )

    assert_equal [[0, 20]], session.merged_ranges
    assert_equal 20, session.received_size
    assert session.complete?
  end

  it "keeps disjoint ranges separate" do
    session = Shrine::ResumableUpload::Session.new(
      total_size: 10,
      ranges: [[5, 10], [0, 3]],
    )

    assert_equal [[0, 3], [5, 10]], session.merged_ranges
    assert_equal 8, session.received_size
    refute session.complete?
  end

  it "treats a zero-length file as complete" do
    session = Shrine::ResumableUpload::Session.new(total_size: 0, ranges: [])
    assert session.complete?
    refute session.finalized?
  end

  it "round-trips through JSON-friendly hashes" do
    original = Shrine::ResumableUpload::Session.new(
      id: "abc", total_size: 12, ranges: [[0, 4], [8, 12]],
      filename: "f.bin", checksum: "sha256=deadbeef",
      uploaded_file_data: { "id" => "x", "storage" => "cache", "metadata" => {} },
    )

    hash = original.to_h
    restored = Shrine::ResumableUpload::Session.from_h(JSON.parse(JSON.generate(hash)))

    assert_equal original.id, restored.id
    assert_equal original.total_size, restored.total_size
    assert_equal original.merged_ranges, restored.merged_ranges
    assert_equal original.checksum, restored.checksum
    assert_nil restored.expires_at
    assert restored.finalized?
  end

  it "reports expiry" do
    session = Shrine::ResumableUpload::Session.new(total_size: 1)
    session.expires_at = Time.now.utc - 1
    assert session.expired?
  end
end
