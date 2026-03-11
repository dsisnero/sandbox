#!/usr/bin/env ruby
# frozen_string_literal: true

require "optparse"
require_relative "parity_inventory_lib"

options = {
  root_dir: Dir.pwd,
  out: nil,
  source_path: ENV["PORT_SOURCE_DIR"],
  language: ENV["PORT_LANGUAGE"] || "go",
  parser: ENV["PORT_PARSER"] || "auto",
  force_overwrite: ENV["PORT_FORCE_OVERWRITE"] == "1"
}

OptionParser.new do |opts|
  opts.banner = "Usage: generate_port_inventory.rb [options]"
  opts.on("--root DIR", "Project root (default: pwd)") { |v| options[:root_dir] = v }
  opts.on("--out FILE", "Output TSV path") { |v| options[:out] = v }
  opts.on("--source PATH", "Source path (absolute or relative to root)") { |v| options[:source_path] = v }
  opts.on("--language LANG", "Language: go|rust|crystal|java|ruby") { |v| options[:language] = v }
  opts.on("--parser MODE", "Parser: auto|regex|tree-sitter") { |v| options[:parser] = v }
  opts.on("--force-overwrite", "Allow overwriting an existing port inventory file") { options[:force_overwrite] = true }
end.parse!

language = options[:language]
out = options[:out] || File.join(options[:root_dir], "plans/inventory/#{language}_port_inventory.tsv")

if File.exist?(out) && !options[:force_overwrite]
  warn "Refusing to overwrite existing inventory: #{out}"
  warn "Use check_port_inventory.sh for drift checks and update statuses manually."
  warn "If you intentionally want to reset, rerun with --force-overwrite or PORT_FORCE_OVERWRITE=1."
  exit 1
end

base, items = ParityInventory.discover_items(
  root_dir: options[:root_dir],
  source_path: options[:source_path],
  language: language,
  parser_mode: options[:parser]
)

if items.empty?
  warn "No #{language} items found under #{base}"
  exit 1
end

ParityInventory.write_inventory(out, items)
count = items.length
puts "Generated #{out} (#{count} items) from #{base}."
