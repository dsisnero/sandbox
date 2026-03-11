#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"
require_relative "parity_inventory_lib"

options = {
  root_dir: Dir.pwd,
  out: nil,
  source_path: ENV["PORT_SOURCE_DIR"],
  language: ENV["PORT_LANGUAGE"] || "go",
  parser: ENV["PORT_PARSER"] || "auto"
}

OptionParser.new do |opts|
  opts.banner = "Usage: generate_test_parity_manifest.rb [options]"
  opts.on("--root DIR", "Project root (default: pwd)") { |v| options[:root_dir] = v }
  opts.on("--out FILE", "Output TSV path") { |v| options[:out] = v }
  opts.on("--source PATH", "Source path (absolute or relative to root)") { |v| options[:source_path] = v }
  opts.on("--language LANG", "Language: go|rust|crystal|java|ruby") { |v| options[:language] = v }
  opts.on("--parser MODE", "Parser: auto|regex|tree-sitter") { |v| options[:parser] = v }
end.parse!

language = options[:language]
out = options[:out] || File.join(options[:root_dir], "plans/inventory/#{language}_test_parity.tsv")

base, items = ParityInventory.discover_items(
  root_dir: options[:root_dir],
  source_path: options[:source_path],
  language: language,
  parser_mode: options[:parser]
)

test_items = items.select { |item| item.scope == "test" }
if test_items.empty?
  warn "No #{language} test items found under #{base}"
  exit 1
end

ParityInventory.write_scope_manifest(out, test_items, scope: "test", header_id: "source_test_id")
puts "Generated #{out} (#{test_items.length} tests) from #{base}."
