# encoding: utf-8

module I18n
  module Tests
    module Pluralization
      test "pluralization: given 0 it returns the :zero translation if it is defined" do
        assert_equal 'zero', I18n.t(:default => { :zero => 'zero' }, :count => 0)
      end

      test "pluralization: given 0 it returns the :other translation if :zero is not defined" do
        assert_equal 'bars', I18n.t(:default => { :other => 'bars' }, :count => 0)
      end

      test "pluralization: given 1 it returns the singular translation" do
        assert_equal 'bar', I18n.t(:default => { :one => 'bar' }, :count => 1)
      end

      test "pluralization: given 2 it returns the :other translation" do
        assert_equal 'bars', I18n.t(:default => { :other => 'bars' }, :count => 2)
      end

      test "pluralization: given 3 it returns the :other translation" do
        assert_equal 'bars', I18n.t(:default => { :other => 'bars' }, :count => 3)
      end

      test "pluralization: given a single-value count range it uses ordinary count pluralization" do
        assert_equal 'bar', I18n.t(:default => { :one => 'bar' }, :count_range => 1..1)
      end

      test "pluralization: given a count range it returns a pluralized and interpolated translation" do
        assert_equal '2–3 bars', I18n.t(:default => { :other => '%{count_range} bars' }, :count_range => 2..3)
      end

      test "pluralization: given an invalid count range it raises an argument error" do
        assert_raises(I18n::InvalidCountRange) do
          I18n.t(:default => { :other => 'bars' }, :count_range => 3..2)
        end
      end

      test "pluralization: given nil it returns the whole entry" do
        assert_equal({ :one => 'bar' }, I18n.t(:default => { :one => 'bar' }, :count => nil))
      end

      test "pluralization: given incomplete pluralization data it raises I18n::InvalidPluralizationData" do
        assert_raises(I18n::InvalidPluralizationData) { I18n.t(:default => { :one => 'bar' }, :count => 2) }
      end
    end
  end
end
