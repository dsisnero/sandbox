#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "set"
require "fileutils"

module ParityInventory
  SUPPORTED_LANGUAGES = %w[go rust crystal java ruby].freeze

  Item = Struct.new(:id, :kind, :scope, :file, :name, keyword_init: true)

  module_function

  def resolve_base(root_dir, source_path)
    root = Pathname(root_dir).expand_path
    if source_path && !source_path.strip.empty?
      candidate = Pathname(source_path)
      return candidate.expand_path if candidate.absolute?

      return (root + candidate).expand_path
    end

    vendor = root + "vendor"
    vendor.exist? ? vendor : root
  end

  def detect_treesitter(language)
    return false unless SUPPORTED_LANGUAGES.include?(language)

    begin
      require "tree_sitter"
      # Common ruby gem names for language grammars.
      possible = [
        "tree_sitter/#{language}",
        "tree_sitter_#{language}",
        "tree-sitter-#{language}"
      ]
      possible.any? do |lib|
        begin
          require lib
          true
        rescue LoadError
          false
        end
      end
    rescue LoadError
      false
    end
  end

  def discover_items(root_dir:, source_path:, language:, parser_mode: "auto")
    raise ArgumentError, "Unsupported language: #{language}" unless SUPPORTED_LANGUAGES.include?(language)

    base = resolve_base(root_dir, source_path)
    raise ArgumentError, "Source directory does not exist: #{base}" unless base.directory?

    parser = effective_parser(language, parser_mode)
    warn "tree-sitter parser unavailable for #{language}; falling back to regex" if parser_mode == "tree-sitter" && parser != "tree-sitter"

    items = if parser == "tree-sitter"
      # Placeholder: parser selection logic is ready; regex extraction remains canonical for now.
      discover_with_regex(base, language)
    else
      discover_with_regex(base, language)
    end

    [base, dedupe_items(items)]
  end

  def effective_parser(language, parser_mode)
    mode = parser_mode.to_s
    return "regex" if mode.empty? || mode == "regex"
    return detect_treesitter(language) ? "tree-sitter" : "regex" if mode == "tree-sitter"
    return detect_treesitter(language) ? "tree-sitter" : "regex" if mode == "auto"

    raise ArgumentError, "Invalid parser mode: #{parser_mode} (expected auto|regex|tree-sitter)"
  end

  def dedupe_items(items)
    seen = Set.new
    items.select do |item|
      key = [item.id, item.kind, item.scope]
      next false if seen.include?(key)

      seen << key
      true
    end.sort_by(&:id)
  end

  def discover_with_regex(base, language)
    entries = files_for_language(base, language)
    source_items = []
    test_items = []

    entries.each do |path, rel|
      content = File.read(path)
      src, test = case language
                  when "go" then extract_go(rel, content)
                  when "rust" then extract_rust(rel, content)
                  when "crystal" then extract_crystal(rel, content)
                  when "java" then extract_java(rel, content)
                  when "ruby" then extract_ruby(rel, content)
                  else [[], []]
                  end
      source_items.concat(src) unless test_file_for_language?(language, rel)
      test_items.concat(test)
    end

    source_items + test_items
  end

  def files_for_language(base, language)
    files = Dir.glob("**/*", File::FNM_DOTMATCH, base: base.to_s)
               .reject { |f| f.start_with?(".") || f.include?("/.git/") || f.end_with?("/.git") }

    selected = files.select do |rel|
      full = base + rel
      next false unless full.file?

      case language
      when "go"
        rel.end_with?(".go")
      when "rust"
        rel.end_with?(".rs")
      when "crystal"
        rel.end_with?(".cr")
      when "java"
        rel.end_with?(".java")
      when "ruby"
        rel.end_with?(".rb")
      else
        false
      end
    end

    selected.sort.map { |rel| [(base + rel).to_s, rel] }
  end

  def emit_source(rel, kind, name)
    Item.new(id: "#{rel}::#{kind}::#{name}", kind: kind, scope: "source", file: rel, name: name)
  end

  def emit_test(rel, name)
    Item.new(id: "#{rel}::test::#{name}", kind: "test", scope: "test", file: rel, name: name)
  end

  def test_file_for_language?(language, rel)
    case language
    when "go"
      rel.end_with?("_test.go")
    when "crystal"
      rel.end_with?("_spec.cr") || rel.start_with?("spec/")
    when "java"
      rel.include?("/test/") || rel.end_with?("Test.java")
    when "ruby"
      rel.end_with?("_spec.rb") || rel.end_with?("_test.rb") || rel.start_with?("spec/") || rel.start_with?("test/")
    else
      false
    end
  end

  def extract_go(rel, text)
    source = []
    tests = []

    in_const_block = false

    text.each_line do |line|
      stripped = line.strip

      if stripped.match?(/^const\s*\(/)
        in_const_block = true
        next
      end

      if in_const_block
        if stripped == ")"
          in_const_block = false
        elsif (m = stripped.match(/^([A-Z][A-Za-z0-9_]*)\b/))
          source << emit_source(rel, "const", m[1])
        end
        next
      end

      if (m = stripped.match(/^const\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, "const", m[1])
      end

      if (m = stripped.match(/^type\s+([A-Z][A-Za-z0-9_]*)\b/))
        kind = stripped.include?(" struct") || stripped.end_with?("struct{") || stripped.end_with?("struct {") ? "struct" : "type"
        source << emit_source(rel, kind, m[1])
      end

      if (m = stripped.match(/^func\s+([A-Z][A-Za-z0-9_]*)\s*\(/))
        source << emit_source(rel, "func", m[1])
      end

      if (m = stripped.match(/^func\s+\(([^)]+)\)\s+([A-Z][A-Za-z0-9_]*)\s*\(/))
        recv = m[1].split.last.to_s.delete("*")
        source << emit_source(rel, "method", "#{recv}.#{m[2]}") unless recv.empty?
      end

      if (m = stripped.match(/^func\s+(Test[A-Za-z0-9_]*)\s*\(/))
        tests << emit_test(rel, m[1])
      end
    end

    [source, tests]
  end

  def extract_rust(rel, text)
    source = []
    tests = []

    pub_impl = nil
    pending_test_attr = false

    text.each_line do |line|
      stripped = line.strip

      if (m = stripped.match(/^pub\s+const\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, "const", m[1])
      end
      if (m = stripped.match(/^pub\s+struct\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, "struct", m[1])
      end
      if (m = stripped.match(/^pub\s+enum\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, "enum", m[1])
      end
      if (m = stripped.match(/^pub\s+trait\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, "trait", m[1])
      end
      if (m = stripped.match(/^pub\s+type\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, "type", m[1])
      end
      if (m = stripped.match(/^pub\s+fn\s+([a-zA-Z_][A-Za-z0-9_]*)\s*\(/))
        source << emit_source(rel, "func", m[1])
      end

      if (m = stripped.match(/^impl(?:<[^>]+>)?\s+([A-Z][A-Za-z0-9_:]*)/))
        pub_impl = m[1]
      elsif stripped.start_with?("}")
        pub_impl = nil
      elsif pub_impl && (m = stripped.match(/^pub\s+fn\s+([a-zA-Z_][A-Za-z0-9_]*)\s*\(/))
        source << emit_source(rel, "method", "#{pub_impl}.#{m[1]}")
      end

      pending_test_attr = true if stripped.start_with?("#[test]")
      if pending_test_attr && (m = stripped.match(/^fn\s+([a-zA-Z_][A-Za-z0-9_]*)\s*\(/))
        tests << emit_test(rel, m[1])
        pending_test_attr = false
      end
    end

    [source, tests]
  end

  def extract_crystal(rel, text)
    source = []
    tests = []

    namespace = []

    text.each_line do |line|
      stripped = line.strip

      if (m = stripped.match(/^(class|module|struct|enum)\s+([A-Z][A-Za-z0-9_:]*)/))
        kind = m[1]
        name = m[2]
        source << emit_source(rel, kind, name)
        namespace << name
        next
      end

      if stripped == "end"
        namespace.pop unless namespace.empty?
        next
      end

      if (m = stripped.match(/^([A-Z][A-Z0-9_]*)\s*=/))
        source << emit_source(rel, "const", m[1])
      end

      if (m = stripped.match(/^def\s+(self\.)?([a-z_][A-Za-z0-9_!?=]*)\b/))
        recv = namespace.last
        name = m[2]
        kind = m[1] ? "func" : "method"
        id_name = recv ? "#{recv}.#{name}" : name
        source << emit_source(rel, kind, id_name)
      end

      if (m = stripped.match(/^it\s+"([^"]+)"/))
        tests << emit_test(rel, m[1])
      end
    end

    if rel.end_with?("_spec.cr")
      text.each_line do |line|
        stripped = line.strip
        if (m = stripped.match(/^describe\s+([A-Za-z0-9_:"'. ]+)/))
          tests << emit_test(rel, m[1])
        end
      end
    end

    [source, tests]
  end

  def extract_java(rel, text)
    source = []
    tests = []

    current_type = nil
    pending_test_attr = false

    text.each_line do |line|
      stripped = line.strip

      if (m = stripped.match(/^public\s+(class|interface|enum|record)\s+([A-Z][A-Za-z0-9_]*)\b/))
        source << emit_source(rel, m[1], m[2])
        current_type = m[2]
      end

      if (m = stripped.match(/^public\s+static\s+final\s+[A-Za-z0-9_<>, ?\[\]]+\s+([A-Z][A-Z0-9_]*)\b/))
        source << emit_source(rel, "const", m[1])
      end

      if (m = stripped.match(/^public\s+(?:static\s+)?[A-Za-z0-9_<>, ?\[\]]+\s+([a-zA-Z_][A-Za-z0-9_]*)\s*\(/))
        next if %w[if for while switch catch].include?(m[1])

        if current_type && m[1] == current_type
          source << emit_source(rel, "ctor", "#{current_type}.#{m[1]}")
        elsif current_type
          source << emit_source(rel, "method", "#{current_type}.#{m[1]}")
        else
          source << emit_source(rel, "func", m[1])
        end
      end

      pending_test_attr = true if stripped == "@Test"
      if pending_test_attr && (m = stripped.match(/^(public\s+)?void\s+([a-zA-Z_][A-Za-z0-9_]*)\s*\(/))
        tests << emit_test(rel, m[2])
        pending_test_attr = false
      end
    end

    [source, tests]
  end

  def extract_ruby(rel, text)
    source = []
    tests = []

    namespace = []

    text.each_line do |line|
      stripped = line.strip

      if (m = stripped.match(/^(class|module)\s+([A-Z][A-Za-z0-9_:]*)/))
        source << emit_source(rel, m[1], m[2])
        namespace << m[2]
        next
      end

      if stripped == "end"
        namespace.pop unless namespace.empty?
        next
      end

      if (m = stripped.match(/^([A-Z][A-Z0-9_]*)\s*=/))
        source << emit_source(rel, "const", m[1])
      end

      if (m = stripped.match(/^def\s+(self\.)?([a-z_][A-Za-z0-9_!?=]*)/))
        recv = namespace.last
        name = m[2]
        kind = m[1] ? "func" : "method"
        source << emit_source(rel, kind, recv ? "#{recv}.#{name}" : name)
      end

      if (m = stripped.match(/^def\s+(test_[A-Za-z0-9_]+)/))
        tests << emit_test(rel, m[1])
      end
      if (m = stripped.match(/^it\s+["'](.+?)["']/))
        tests << emit_test(rel, m[1])
      end
      if (m = stripped.match(/^test\s+["'](.+?)["']/))
        tests << emit_test(rel, m[1])
      end
    end

    [source, tests]
  end

  def write_inventory(path, items)
    FileUtils.mkdir_p(File.dirname(path))
    File.open(path, "w") do |f|
      f.puts "# source_id\tkind\tstatus\tcrystal_refs\tnotes"
      items.each do |item|
        f.puts "#{item.id}\t#{item.kind}\tmissing\t-\tauto-generated"
      end
    end
  end

  def write_scope_manifest(path, items, scope:, header_id:, notes_overrides: {})
    FileUtils.mkdir_p(File.dirname(path))
    File.open(path, "w") do |f|
      f.puts "# #{header_id}\tstatus\tcrystal_refs\tnotes"
      items.select { |item| item.scope == scope }
           .sort_by(&:id)
           .each do |item|
        notes = notes_overrides[item.id] || "baseline"
        f.puts "#{item.id}\tmissing\t-\t#{notes}"
      end
    end
  end

  def load_notes_overrides(path)
    return {} unless path && File.file?(path)

    overrides = {}
    File.readlines(path, chomp: true).each_with_index do |line, idx|
      next if line.start_with?("#") || line.strip.empty?

      cols = line.split("\t", -1)
      if cols.length < 2
        raise "Malformed notes override row #{idx + 1} in #{path}: expected 2 columns (source_api_id\\tnotes)"
      end

      source_id = cols[0].to_s.strip
      note = cols[1].to_s.strip
      next if source_id.empty?

      overrides[source_id] = note.empty? ? "-" : note
    end
    overrides
  end

  def load_manifest_rows(path, min_cols:)
    rows = []
    File.readlines(path, chomp: true).each_with_index do |line, idx|
      next if line.start_with?("#") || line.strip.empty?

      cols = line.split("\t", -1)
      raise "Malformed manifest row #{idx + 1} in #{path}: expected >= #{min_cols} columns" if cols.length < min_cols

      rows << cols
    end
    rows
  end
end
