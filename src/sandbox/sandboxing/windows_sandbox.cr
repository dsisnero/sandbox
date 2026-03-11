require "base64"
require "json"
require "log"
require "random/secure"

module Sandbox
  module Sandboxing
    module WindowsSandbox
      LOG_FILE_NAME                    = "sandbox.log"
      LOG_COMMAND_PREVIEW_LIMIT        = 200
      HELPER_BIN_DIR_NAME              = ".sandbox-bin"
      LOGGER                           = Log.for("sandbox.windows")
      SANDBOX_HOME_ENV_VAR             = "SANDBOX_HOME"
      WINDOWS_INSECURE_FALLBACK_ENV    = "SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"
      USERPROFILE_READ_ROOT_EXCLUSIONS = {
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".kube",
        ".docker",
        ".config",
        ".npm",
        ".pki",
        ".terraform.d",
      }
      DEFAULT_SANDBOX_USERS_GROUP = "CodexSandboxUsers"
      SETUP_VERSION               = 5
      DEFAULT_OFFLINE_USERNAME    = "CodexSandboxOffline"
      DEFAULT_ONLINE_USERNAME     = "CodexSandboxOnline"
      MAX_ITEMS_PER_DIR           = 1000
      AUDIT_TIME_LIMIT            = 2.seconds
      MAX_CHECKED_LIMIT           = 50_000
      AUDIT_SKIP_DIR_SUFFIXES     = {
        "/windows/installer",
        "/windows/registration",
        "/programdata",
      }

      enum PolicyKind
        ReadOnly
        WorkspaceWrite
        DangerFullAccess
        ExternalSandbox
      end

      struct Policy
        getter kind : PolicyKind
        getter? network_access : Bool
        getter writable_roots : Array(String)
        getter? exclude_tmpdir_env_var : Bool
        getter? exclude_slash_tmp : Bool

        def initialize(
          @kind : PolicyKind,
          @network_access : Bool = false,
          @writable_roots : Array(String) = [] of String,
          @exclude_tmpdir_env_var : Bool = false,
          @exclude_slash_tmp : Bool = false,
        )
        end

        def self.read_only : self
          new(PolicyKind::ReadOnly, false)
        end

        def self.workspace_write(
          network_access : Bool = false,
          writable_roots : Array(String) = [] of String,
          exclude_tmpdir_env_var : Bool = false,
          exclude_slash_tmp : Bool = false,
        ) : self
          new(
            PolicyKind::WorkspaceWrite,
            network_access,
            writable_roots,
            exclude_tmpdir_env_var,
            exclude_slash_tmp
          )
        end
      end

      struct CaptureResult
        getter exit_code : Int32
        getter stdout : Bytes
        getter stderr : Bytes
        getter? timed_out : Bool

        def initialize(
          @exit_code : Int32 = 1,
          @stdout : Bytes = Bytes.empty,
          @stderr : Bytes = Bytes.empty,
          @timed_out : Bool = false,
        )
        end
      end

      struct AllowDenyPaths
        getter allow : Set(String)
        getter deny : Set(String)

        def initialize(
          @allow : Set(String) = Set(String).new,
          @deny : Set(String) = Set(String).new,
        )
        end
      end

      struct SandboxCreds
        include JSON::Serializable
        getter offline_username : String
        getter online_username : String

        def initialize(
          @offline_username : String = WindowsSandbox.offline_username,
          @online_username : String = WindowsSandbox.online_username,
        )
        end
      end

      struct SetupErrorReport
        include JSON::Serializable
        getter code : SetupErrorCode
        getter message : String

        def initialize(@code : SetupErrorCode, @message : String)
        end
      end

      struct SandboxUserRecord
        include JSON::Serializable
        getter username : String
        getter password : String

        def initialize(@username : String, @password : String)
        end
      end

      struct SandboxUsersFile
        include JSON::Serializable
        getter version : Int32
        getter offline : SandboxUserRecord
        getter online : SandboxUserRecord

        def initialize(
          @version : Int32 = SETUP_VERSION,
          @offline : SandboxUserRecord = SandboxUserRecord.new(WindowsSandbox.offline_username, ""),
          @online : SandboxUserRecord = SandboxUserRecord.new(WindowsSandbox.online_username, ""),
        )
        end

        def version_matches : Bool
          version == SETUP_VERSION
        end
      end

      struct SetupMarker
        include JSON::Serializable
        getter version : Int32
        getter offline_username : String
        getter online_username : String

        def initialize(
          @version : Int32 = SETUP_VERSION,
          @offline_username : String = WindowsSandbox.offline_username,
          @online_username : String = WindowsSandbox.online_username,
        )
        end

        def version_matches : Bool
          version == SETUP_VERSION
        end
      end

      struct CapSids
        include JSON::Serializable
        getter workspace : String
        getter readonly : String
        getter workspace_by_cwd : Hash(String, String)

        def initialize(
          @workspace : String,
          @readonly : String,
          @workspace_by_cwd : Hash(String, String) = Hash(String, String).new,
        )
        end
      end

      struct ReadAclMutexGuard
        getter? acquired : Bool

        def initialize(@acquired : Bool = true)
        end
      end

      enum SetupErrorCode
        OrchestratorSandboxDirCreateFailed
        OrchestratorElevationCheckFailed
        OrchestratorPayloadSerializeFailed
        OrchestratorHelperLaunchFailed
        OrchestratorHelperLaunchCanceled
        OrchestratorHelperExitNonzero
        OrchestratorHelperReportReadFailed
        HelperRequestArgsFailed
        HelperSandboxDirCreateFailed
        HelperLogFailed
        HelperUserProvisionFailed
        HelperUsersGroupCreateFailed
        HelperUserCreateOrUpdateFailed
        HelperDpapiProtectFailed
        HelperUsersFileWriteFailed
        HelperSetupMarkerWriteFailed
        HelperSidResolveFailed
        HelperCapabilitySidFailed
        HelperFirewallComInitFailed
        HelperFirewallPolicyAccessFailed
        HelperFirewallRuleCreateOrAddFailed
        HelperFirewallRuleVerifyFailed
        HelperReadAclHelperSpawnFailed
        HelperSandboxLockFailed
        HelperUnknownError

        def as_str : String
          case self
          in .orchestrator_sandbox_dir_create_failed?
            "orchestrator_sandbox_dir_create_failed"
          in .orchestrator_elevation_check_failed?
            "orchestrator_elevation_check_failed"
          in .orchestrator_payload_serialize_failed?
            "orchestrator_payload_serialize_failed"
          in .orchestrator_helper_launch_failed?
            "orchestrator_helper_launch_failed"
          in .orchestrator_helper_launch_canceled?
            "orchestrator_helper_launch_canceled"
          in .orchestrator_helper_exit_nonzero?
            "orchestrator_helper_exit_nonzero"
          in .orchestrator_helper_report_read_failed?
            "orchestrator_helper_report_read_failed"
          in .helper_request_args_failed?
            "helper_request_args_failed"
          in .helper_sandbox_dir_create_failed?
            "helper_sandbox_dir_create_failed"
          in .helper_log_failed?
            "helper_log_failed"
          in .helper_user_provision_failed?
            "helper_user_provision_failed"
          in .helper_users_group_create_failed?
            "helper_users_group_create_failed"
          in .helper_user_create_or_update_failed?
            "helper_user_create_or_update_failed"
          in .helper_dpapi_protect_failed?
            "helper_dpapi_protect_failed"
          in .helper_users_file_write_failed?
            "helper_users_file_write_failed"
          in .helper_setup_marker_write_failed?
            "helper_setup_marker_write_failed"
          in .helper_sid_resolve_failed?
            "helper_sid_resolve_failed"
          in .helper_capability_sid_failed?
            "helper_capability_sid_failed"
          in .helper_firewall_com_init_failed?
            "helper_firewall_com_init_failed"
          in .helper_firewall_policy_access_failed?
            "helper_firewall_policy_access_failed"
          in .helper_firewall_rule_create_or_add_failed?
            "helper_firewall_rule_create_or_add_failed"
          in .helper_firewall_rule_verify_failed?
            "helper_firewall_rule_verify_failed"
          in .helper_read_acl_helper_spawn_failed?
            "helper_read_acl_helper_spawn_failed"
          in .helper_sandbox_lock_failed?
            "helper_sandbox_lock_failed"
          in .helper_unknown_error?
            "helper_unknown_error"
          end
        end
      end

      class SetupFailure < Exception
        getter code : SetupErrorCode

        def initialize(@code : SetupErrorCode, message : String)
          super(message)
        end

        def metric_message : String
          WindowsSandbox.sanitize_setup_metric_tag_value(message || "")
        end
      end

      enum CopyOutcome
        Reused
        ReCopied
      end

      def self.validate_supported_level(level : WindowsSandboxLevel) : Nil
        return if level.disabled? || level.restricted_token?
        raise "unsupported Windows sandbox level: #{level}"
      end

      @@sandbox_home_override : String? = nil
      @@sandbox_users_group_override : String? = nil
      @@offline_username_override : String? = nil
      @@online_username_override : String? = nil

      def self.sandbox_home : String
        @@sandbox_home_override || ENV[SANDBOX_HOME_ENV_VAR]? || Dir.current
      end

      def self.sandbox_home=(value : String) : String
        @@sandbox_home_override = value
        value
      end

      def self.sandbox_users_group : String
        @@sandbox_users_group_override || DEFAULT_SANDBOX_USERS_GROUP
      end

      def self.sandbox_users_group=(value : String) : String
        @@sandbox_users_group_override = value
        value
      end

      def self.offline_username : String
        @@offline_username_override || DEFAULT_OFFLINE_USERNAME
      end

      def self.offline_username=(value : String) : String
        @@offline_username_override = value
        value
      end

      def self.online_username : String
        @@online_username_override || DEFAULT_ONLINE_USERNAME
      end

      def self.online_username=(value : String) : String
        @@online_username_override = value
        value
      end

      def self.run_windows_sandbox_capture(
        policy_json_or_preset : String,
        command : Array(String),
        cwd : String,
        env_map : Hash(String, String),
        timeout_ms : UInt64? = nil,
      ) : CaptureResult
        {% unless flag?(:win32) %}
          return CaptureResult.new(
            exit_code: 1,
            stdout: Bytes.empty,
            stderr: "Windows sandbox is only available on Windows".to_slice,
            timed_out: false
          )
        {% end %}

        unless windows_insecure_fallback_enabled?
          return CaptureResult.new(
            exit_code: 1,
            stdout: Bytes.empty,
            stderr: "Windows restricted-token backend is required; insecure fallback disabled".to_slice,
            timed_out: false
          )
        end

        policy = parse_policy(policy_json_or_preset)
        raise "No command specified to execute." if command.empty?

        env = env_map.dup
        normalize_null_device_env(env)
        ensure_non_interactive_pager(env)
        inherit_path_env(env)
        apply_no_network_to_env(env) if should_apply_network_block(policy)
        allow_deny_paths = compute_allow_paths(policy, cwd, cwd, env)
        logs_base_dir = sandbox_dir

        stdout_io = IO::Memory.new
        stderr_io = IO::Memory.new

        program = command.first
        args = command[1..]
        Dir.mkdir_p(logs_base_dir)
        log_start(command, logs_base_dir)
        debug_log(
          "policy_allow_roots=#{allow_deny_paths.allow.size} policy_deny_roots=#{allow_deny_paths.deny.size}",
          logs_base_dir,
          env
        )
        process = Process.new(
          program,
          args: args,
          input: Process::Redirect::Close,
          output: stdout_io,
          error: stderr_io,
          env: env,
          chdir: cwd
        )

        status_channel = Channel(Process::Status).new
        spawn do
          status_channel.send(process.wait)
        end

        timed_out = false
        status = if timeout_ms
                   select
                   when completed = status_channel.receive
                     completed
                   when timeout(timeout_ms.milliseconds)
                     process.terminate(graceful: false)
                     timed_out = true
                     status_channel.receive
                   end
                 else
                   status_channel.receive
                 end
        exit_code = timed_out ? 192 : status.exit_code
        if exit_code == 0
          log_success(command, logs_base_dir)
        else
          log_failure(command, "exit code #{exit_code}", logs_base_dir)
        end
        CaptureResult.new(
          exit_code: exit_code,
          stdout: stdout_io.to_slice,
          stderr: stderr_io.to_slice,
          timed_out: timed_out
        )
      rescue ex
        CaptureResult.new(
          exit_code: 1,
          stdout: Bytes.empty,
          stderr: (ex.message || "run_windows_sandbox_capture failed").to_slice,
          timed_out: false
        )
      end

      def self.run_windows_sandbox_legacy_preflight(
        sandbox_policy : Policy,
        policy_cwd : String = Dir.current,
        cwd : String = Dir.current,
        env_map : Hash(String, String) = Hash(String, String).new,
      ) : Nil
        {% if flag?(:win32) %}
          raise "Windows restricted-token backend is required; insecure fallback disabled" unless windows_insecure_fallback_enabled?
          _ = compute_allow_paths(sandbox_policy, policy_cwd, cwd, env_map)
          nil
        {% else %}
          _ = sandbox_policy
          _ = policy_cwd
          _ = cwd
          _ = env_map
          raise "Windows sandbox is only available on Windows"
        {% end %}
      end

      def self.parse_policy(value : String) : Policy
        case value
        when "read-only"
          Policy.read_only
        when "workspace-write"
          Policy.workspace_write(network_access: false)
        when "danger-full-access", "external-sandbox"
          raise "DangerFullAccess and ExternalSandbox are not supported for sandboxing"
        else
          parsed = JSON.parse(value).as_h?
          raise "Unsupported Windows sandbox policy payload" unless parsed
          parse_policy_json_object(parsed)
        end
      end

      def self.should_apply_network_block(policy : Policy) : Bool
        case policy.kind
        in .read_only?
          true
        in .workspace_write?
          !policy.network_access?
        in .danger_full_access?, .external_sandbox?
          false
        end
      end

      def self.canonicalize_path(path : String) : String
        File.realpath(path)
      rescue
        path
      end

      def self.canonical_path_key(path : String) : String
        canonicalize_path(path).gsub('\\', '/').downcase
      end

      def self.preview_command(command : Array(String)) : String
        joined = command.join(" ")
        return joined if joined.bytesize <= LOG_COMMAND_PREVIEW_LIMIT

        builder = String::Builder.new
        bytes = 0
        joined.each_char do |char|
          char_bytes = char.bytesize
          break if bytes + char_bytes > LOG_COMMAND_PREVIEW_LIMIT

          builder << char
          bytes += char_bytes
        end
        builder.to_s
      end

      def self.log_start(command : Array(String), base_dir : String? = nil) : Nil
        log_note("START: #{preview_command(command)}", base_dir)
      end

      def self.log_success(command : Array(String), base_dir : String? = nil) : Nil
        log_note("SUCCESS: #{preview_command(command)}", base_dir)
      end

      def self.log_failure(command : Array(String), detail : String, base_dir : String? = nil) : Nil
        log_note("FAILURE: #{preview_command(command)} (#{detail})", base_dir)
      end

      def self.debug_log(
        message : String,
        base_dir : String? = nil,
        env_map : Hash(String, String)? = nil,
      ) : Nil
        source = env_map || ENV.to_h
        return unless source["SBX_DEBUG"]? == "1"

        LOGGER.debug { message }
        append_line("DEBUG: #{message}", base_dir)
        STDERR.puts(message)
      end

      def self.log_note(message : String, base_dir : String? = nil) : Nil
        formatted = "[#{Time.local.to_s("%Y-%m-%d %H:%M:%S.%3N")} #{exe_label}] #{message}"
        LOGGER.info { formatted }
        append_line(formatted, base_dir)
      end

      def self.redact_username_segments(
        value : String,
        usernames : Array(String),
        case_insensitive : Bool = true,
      ) : String
        return value if usernames.empty?

        segments = [] of String
        separators = [] of Char
        current = String::Builder.new

        value.each_char do |char|
          if char == '\\' || char == '/'
            segments << current.to_s
            current = String::Builder.new
            separators << char
          else
            current << char
          end
        end
        segments << current.to_s

        redacted_segments = segments.map do |segment|
          matched = usernames.any? do |name|
            if case_insensitive
              segment.compare(name, case_insensitive: true) == 0
            else
              segment == name
            end
          end
          matched ? "<user>" : segment
        end

        out = String::Builder.new
        redacted_segments.each_with_index do |segment, index|
          out << segment
          separator = separators[index]?
          out << separator if separator
        end
        out.to_s
      end

      def self.sanitize_setup_metric_tag_value(value : String) : String
        usernames = [] of String
        {"USERNAME", "USER"}.each do |key|
          username = ENV[key]?
          next unless username
          trimmed = username.strip
          next if trimmed.empty?
          next if usernames.any? { |existing| existing.compare(trimmed, case_insensitive: true) == 0 }
          usernames << trimmed
        end

        redacted = redact_username_segments(value, usernames)
        lowered = redacted.downcase
        sanitized = lowered.gsub(/[^a-z0-9_]/, "_").gsub(/_+/, "_")
        sanitized.gsub(/^_+|_+$/, "")
      end

      def self.normalize_null_device_env(env_map : Hash(String, String)) : Nil
        keys = env_map.keys.dup
        keys.each do |key|
          value = env_map[key]?
          next unless value
          lowered = value.strip.downcase
          if lowered == "/dev/null" || lowered == "\\\\dev\\\\null"
            env_map[key] = "NUL"
          end
        end
      end

      def self.ensure_non_interactive_pager(env_map : Hash(String, String)) : Nil
        env_map["GIT_PAGER"] ||= "more.com"
        env_map["PAGER"] ||= "more.com"
        env_map["LESS"] ||= ""
      end

      def self.inherit_path_env(
        env_map : Hash(String, String),
        inherited_env : Hash(String, String)? = nil,
      ) : Nil
        source = inherited_env || ENV.to_h
        if !env_map.has_key?("PATH") && (path = source["PATH"]?)
          env_map["PATH"] = path
        end
        if !env_map.has_key?("PATHEXT") && (pathext = source["PATHEXT"]?)
          env_map["PATHEXT"] = pathext
        end
      end

      def self.apply_no_network_to_env(env_map : Hash(String, String)) : Nil
        env_map["SBX_NONET_ACTIVE"] ||= "1"
        env_map["HTTP_PROXY"] ||= "http://127.0.0.1:9"
        env_map["HTTPS_PROXY"] ||= "http://127.0.0.1:9"
        env_map["ALL_PROXY"] ||= "http://127.0.0.1:9"
        env_map["NO_PROXY"] ||= "localhost,127.0.0.1,::1"
        env_map["PIP_NO_INDEX"] ||= "1"
        env_map["PIP_DISABLE_PIP_VERSION_CHECK"] ||= "1"
        env_map["NPM_CONFIG_OFFLINE"] ||= "true"
        env_map["CARGO_NET_OFFLINE"] ||= "true"
        env_map["GIT_HTTP_PROXY"] ||= "http://127.0.0.1:9"
        env_map["GIT_HTTPS_PROXY"] ||= "http://127.0.0.1:9"
        env_map["GIT_SSH_COMMAND"] ||= "cmd /c exit 1"
        env_map["GIT_ALLOW_PROTOCOLS"] ||= ""
      end

      def self.compute_allow_paths(
        policy_cwd : String,
        command_cwd : String,
        writable_roots : Array(String) = [] of String,
        exclude_tmpdir_env_var : Bool = false,
        exclude_slash_tmp : Bool = false,
        env_map : Hash(String, String) = Hash(String, String).new,
      ) : AllowDenyPaths
        allow = Set(String).new
        deny = Set(String).new

        add_writable_root = ->(root : String) do
          candidate = absolute_path_like?(root) ? root : File.join(policy_cwd, root)
          canonical = canonicalize_path(candidate)
          if path_exists?(canonical)
            allow.add(canonical)
          end

          {".git", ".codex", ".agents"}.each do |protected_subdir|
            protected_entry = File.join(canonical, protected_subdir)
            if path_exists?(protected_entry)
              deny.add(canonicalize_path(protected_entry))
            end
          end
        end

        add_writable_root.call(command_cwd)
        writable_roots.each { |root| add_writable_root.call(root) }

        unless exclude_tmpdir_env_var
          {"TEMP", "TMP"}.each do |key|
            value = env_map[key]? || ENV[key]?
            next unless value
            canonical = canonicalize_path(value)
            next if exclude_slash_tmp && canonical_path_key(canonical) == "/tmp"
            allow.add(canonical) if path_exists?(canonical)
          end
        end

        AllowDenyPaths.new(allow, deny)
      end

      def self.compute_allow_paths(
        policy : Policy,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String) = Hash(String, String).new,
      ) : AllowDenyPaths
        case policy.kind
        in .workspace_write?
          compute_allow_paths(
            policy_cwd: policy_cwd,
            command_cwd: command_cwd,
            writable_roots: policy.writable_roots,
            exclude_tmpdir_env_var: policy.exclude_tmpdir_env_var?,
            exclude_slash_tmp: policy.exclude_slash_tmp?,
            env_map: env_map
          )
        in .read_only?, .danger_full_access?, .external_sandbox?
          AllowDenyPaths.new
        end
      end

      def self.path_mask_allows(path : String, allowed_roots : Set(String), denied_roots : Set(String)) : Bool
        canonical_path = canonical_path_key(path)
        return false if denied_roots.any? { |deny| path_within_root?(canonical_path, canonical_path_key(deny)) }
        allowed_roots.any? { |allow| path_within_root?(canonical_path, canonical_path_key(allow)) }
      end

      def self.helper_bin_dir(home_dir : String = sandbox_home) : String
        File.join(home_dir, HELPER_BIN_DIR_NAME)
      end

      def self.sandbox_dir(home_dir : String = sandbox_home) : String
        File.join(home_dir, ".sandbox")
      end

      def self.sandbox_bin_dir(home_dir : String = sandbox_home) : String
        File.join(home_dir, ".sandbox-bin")
      end

      def self.sandbox_secrets_dir(home_dir : String = sandbox_home) : String
        File.join(home_dir, ".sandbox-secrets")
      end

      def self.setup_marker_path(home_dir : String = sandbox_home) : String
        File.join(sandbox_dir(home_dir), "setup_marker.json")
      end

      def self.sandbox_users_path(home_dir : String = sandbox_home) : String
        File.join(sandbox_secrets_dir(home_dir), "sandbox_users.json")
      end

      def self.cap_sid_file(home_dir : String = sandbox_home) : String
        File.join(home_dir, "cap_sid")
      end

      def self.destination_is_fresh(source : String, destination : String) : Bool
        source_info = File.info?(source) || return false
        destination_info = File.info?(destination) || return false
        return false unless source_info.size == destination_info.size

        destination_info.modification_time >= source_info.modification_time
      end

      def self.copy_from_source_if_needed(source : String, destination : String) : CopyOutcome
        return CopyOutcome::Reused if destination_is_fresh(source, destination)

        destination_dir = File.dirname(destination)
        Dir.mkdir_p(destination_dir)

        tmp_destination = "#{destination}.tmp-#{Random.rand(1_000_000)}"
        begin
          File.copy(source, tmp_destination)
          File.rename(tmp_destination, destination)
          CopyOutcome::ReCopied
        ensure
          File.delete(tmp_destination) if File.exists?(tmp_destination)
        end
      end

      def self.generate_cap_sid : String
        a = Random.rand(UInt32)
        b = Random.rand(UInt32)
        c = Random.rand(UInt32)
        d = Random.rand(UInt32)
        "S-1-5-21-#{a}-#{b}-#{c}-#{d}"
      end

      def self.workspace_sid_key(cwd : String) : String
        canonical_path_key(cwd)
      end

      def self.workspace_cap_sid_for_cwd(
        workspace_by_cwd : Hash(String, String),
        cwd : String,
      ) : String
        key = workspace_sid_key(cwd)
        workspace_by_cwd[key] ||= generate_cap_sid
      end

      def self.load_or_create_cap_sids(home_dir : String = sandbox_home) : CapSids
        path = cap_sid_file(home_dir)
        if File.exists?(path)
          text = File.read(path).strip
          unless text.empty?
            return CapSids.from_json(text)
          end
        end
        caps = CapSids.new(
          workspace: generate_cap_sid,
          readonly: generate_cap_sid
        )
        Dir.mkdir_p(File.dirname(path))
        File.write(path, caps.to_json)
        caps
      rescue
        CapSids.new(workspace: generate_cap_sid, readonly: generate_cap_sid)
      end

      def self.gather_candidates(
        cwd : String,
        env_map : Hash(String, String),
      ) : Array(String)
        seen = Set(String).new
        candidates = [] of String
        unique_push_candidate(candidates, seen, cwd)

        {"TEMP", "TMP"}.each do |key|
          if value = env_map[key]?
            unique_push_candidate(candidates, seen, value)
          end
        end

        if path_value = env_map["PATH"]?
          path_value.split(';').each do |part|
            next if part.empty?
            unique_push_candidate(candidates, seen, part)
          end
        end

        candidates
      end

      def self.read_request_file(request_path : String) : String
        content = File.read(request_path)
        File.delete(request_path) if File.exists?(request_path)
        content
      end

      def self.main(request_path : String) : String
        read_request_file(request_path)
      end

      def self.resolve_current_exe_for_launch(
        home_dir : String,
        fallback_executable : String,
      ) : String
        current = Process.executable_path
        return fallback_executable unless current

        destination = File.join(helper_bin_dir(home_dir), File.basename(current))
        copy_from_source_if_needed(current, destination)
        destination
      rescue
        current || fallback_executable
      end

      def self.resolve_current_exe_for_launch(
        fallback_executable : String,
      ) : String
        resolve_current_exe_for_launch(sandbox_home, fallback_executable)
      end

      def self.create_cwd_junction(cwd : String, _log_dir : String? = nil) : String
        cwd
      end

      def self.protect(secret : String) : String
        Base64.strict_encode(secret)
      end

      def self.unprotect(secret : String) : String
        String.new(Base64.decode(secret))
      end

      def self.ensure_offline_outbound_block : Bool
        true
      end

      def self.audit_everyone_writable(
        cwd : String,
        env_map : Hash(String, String),
      ) : Array(String)
        start_time = Time.instant
        flagged = [] of String
        seen = Set(String).new
        checked = 0

        checked = scan_cwd_children_for_world_writable(cwd, start_time, checked, seen, flagged)
        checked = scan_candidate_roots_for_world_writable(
          cwd,
          env_map,
          start_time,
          checked,
          seen,
          flagged
        )

        elapsed_ms = (Time.instant - start_time).total_milliseconds.to_i
        if flagged.empty?
          log_note(
            "AUDIT: world-writable scan OK; checked=#{checked}; duration_ms=#{elapsed_ms}"
          )
        else
          log_note(
            "AUDIT: world-writable scan FAILED; cwd=#{cwd}; checked=#{checked}; duration_ms=#{elapsed_ms}; flagged=#{flagged.join(",")}"
          )
        end
        flagged
      end

      def self.apply_capability_denies_for_world_writable(
        flagged : Array(String),
        sandbox_policy : String,
        cwd : String,
        home_dir : String = sandbox_home,
      ) : Nil
        _ = home_dir
        _ = sandbox_policy
        return if flagged.empty?

        writable_root = canonical_path_key(cwd)
        filtered = flagged.reject do |path|
          canonical_path_key(path).starts_with?(writable_root)
        end
        return if filtered.empty?

        filtered.each do |path|
          harden_write_permissions(path)
        end
        log_note("AUDIT: hardened world-writable paths=#{filtered.join(",")}")
      end

      def self.apply_world_writable_scan_and_denies(
        cwd : String,
        env_map : Hash(String, String),
        sandbox_policy : String,
        home_dir : String = sandbox_home,
      ) : Nil
        flagged = audit_everyone_writable(cwd, env_map)
        apply_capability_denies_for_world_writable(flagged, sandbox_policy, cwd, home_dir)
      end

      def self.hide_current_user_profile_dir(home_dir : String = sandbox_home) : Nil
        profile = ENV["USERPROFILE"]? || ENV["HOME"]?
        return unless profile
        return unless Dir.exists?(profile)

        append_unique_metadata_entry(
          File.join(sandbox_dir(home_dir), "hidden_profile_dirs.json"),
          canonicalize_path(profile)
        )
      end

      def self.hide_newly_created_users(
        usernames : Array(String) = [offline_username, online_username],
        home_dir : String = sandbox_home,
      ) : Nil
        return if usernames.empty?

        usernames.each do |username|
          append_unique_metadata_entry(
            File.join(sandbox_dir(home_dir), "hidden_users.json"),
            username
          )
        end
      end

      def self.require_logon_sandbox_creds : SandboxCreds
        SandboxCreds.new
      end

      def self.sandbox_setup_is_complete(home_dir : String = sandbox_home) : Bool
        File.exists?(setup_marker_path(home_dir)) && File.exists?(sandbox_users_path(home_dir))
      end

      def self.make_env_block(env_map : Hash(String, String)) : String
        parts = env_map.map { |k, v| {k, v} }
        parts.sort_by! { |(k, _)| {k.upcase, k} }
        block = String::Builder.new
        parts.each do |(k, v)|
          block << k
          block << '='
          block << v
          block << '\0'
        end
        block << '\0'
        block.to_s
      end

      def self.acquire_read_acl_mutex : Bool
        true
      end

      def self.read_acl_mutex_exists : Bool
        false
      end

      def self.ensure_local_group(_name : String = sandbox_users_group) : Bool
        {% if flag?(:win32) %}
          result = run_command_capture("net", ["localgroup", _name])
          return true if result[0].success?
          create_result = run_command_capture("net", ["localgroup", _name, "/add"])
          return true if create_result[0].success?
          return true if command_indicates_existing?(create_result[1], create_result[2])
          raise SetupFailure.new(
            SetupErrorCode::HelperUsersGroupCreateFailed,
            "failed to ensure local group #{_name}: #{create_result[2].strip}"
          )
        {% else %}
          raise "Windows sandbox is only available on Windows"
        {% end %}
      end

      def self.ensure_local_group_member(_group_name : String, _username : String) : Bool
        {% if flag?(:win32) %}
          result = run_command_capture(
            "net",
            ["localgroup", _group_name, _username, "/add"]
          )
          return true if result[0].success?
          return true if command_indicates_existing?(result[1], result[2])
          raise SetupFailure.new(
            SetupErrorCode::HelperUserCreateOrUpdateFailed,
            "failed to add #{_username} to group #{_group_name}: #{result[2].strip}"
          )
        {% else %}
          raise "Windows sandbox is only available on Windows"
        {% end %}
      end

      def self.ensure_local_user(_username : String) : Bool
        {% if flag?(:win32) %}
          result = run_command_capture("net", ["user", _username])
          return true if result[0].success?
          password = "Sbx!#{Random::Secure.hex(16)}"
          create_result = run_command_capture(
            "net",
            ["user", _username, password, "/add", "/y"]
          )
          return true if create_result[0].success?
          return true if command_indicates_existing?(create_result[1], create_result[2])
          raise SetupFailure.new(
            SetupErrorCode::HelperUserCreateOrUpdateFailed,
            "failed to ensure local user #{_username}: #{create_result[2].strip}"
          )
        {% else %}
          raise "Windows sandbox is only available on Windows"
        {% end %}
      end

      def self.ensure_sandbox_user(username : String) : Bool
        ensure_local_user(username)
      end

      def self.ensure_sandbox_users_group : Bool
        ensure_local_group(sandbox_users_group)
      end

      def self.resolve_sid(value : String) : String
        {% if flag?(:win32) %}
          script = "$acct = New-Object System.Security.Principal.NTAccount('#{powershell_single_quote_escape(value)}'); " \
                   "$acct.Translate([System.Security.Principal.SecurityIdentifier]).Value"
          result = run_command_capture(
            "powershell",
            ["-NoProfile", "-NonInteractive", "-Command", script]
          )
          if result[0].success?
            sid = result[1].lines.first?.to_s.strip
            return sid unless sid.empty?
          end
          raise SetupFailure.new(
            SetupErrorCode::HelperSidResolveFailed,
            "failed to resolve SID for #{value}: #{result[2].strip}"
          )
        {% else %}
          raise "Windows sandbox is only available on Windows"
        {% end %}
      end

      def self.resolve_sandbox_users_group_sid : String
        resolve_sid(sandbox_users_group)
      end

      def self.sid_bytes_to_psid(bytes : Bytes) : String
        raise ArgumentError.new("SID bytes too short") if bytes.size < 8

        revision = bytes[0]
        sub_authority_count = bytes[1]
        required = 8 + (sub_authority_count.to_i * 4)
        raise ArgumentError.new("SID bytes truncated") if bytes.size < required

        identifier_authority = 0_u64
        6.times do |index|
          identifier_authority = (identifier_authority << 8) | bytes[2 + index].to_u64
        end

        sid = String::Builder.new
        sid << "S-"
        sid << revision
        sid << "-"
        sid << identifier_authority

        sub_authority_count.times do |index|
          offset = 8 + (index.to_i * 4)
          sub = bytes[offset].to_u32 |
                (bytes[offset + 1].to_u32 << 8) |
                (bytes[offset + 2].to_u32 << 16) |
                (bytes[offset + 3].to_u32 << 24)
          sid << "-"
          sid << sub
        end

        sid.to_s
      end

      def self.provision_sandbox_users : Bool
        ensure_sandbox_users_group &&
          ensure_sandbox_user(offline_username) &&
          ensure_sandbox_user(online_username) &&
          ensure_local_group_member(sandbox_users_group, offline_username) &&
          ensure_local_group_member(sandbox_users_group, online_username)
      rescue ex : SetupFailure
        raise ex
      rescue ex
        raise SetupFailure.new(
          SetupErrorCode::HelperUserProvisionFailed,
          ex.message || "sandbox user provisioning failed"
        )
      end

      def self.setup_error_path(home_dir : String = sandbox_home) : String
        File.join(sandbox_dir(home_dir), "setup_error.json")
      end

      def self.clear_setup_error_report(home_dir : String = sandbox_home) : Nil
        path = setup_error_path(home_dir)
        File.delete(path) if File.exists?(path)
      end

      def self.write_setup_error_report(report : SetupErrorReport, home_dir : String = sandbox_home) : Nil
        path = setup_error_path(home_dir)
        Dir.mkdir_p(File.dirname(path))
        File.write(path, report.to_json)
      end

      def self.write_setup_error_report(home_dir : String, report : SetupErrorReport) : Nil
        write_setup_error_report(report, home_dir)
      end

      def self.read_setup_error_report(home_dir : String = sandbox_home) : SetupErrorReport?
        path = setup_error_path(home_dir)
        if File.exists?(path)
          SetupErrorReport.from_json(File.read(path))
        end
      end

      def self.as_str(code : SetupErrorCode) : String
        code.as_str
      end

      def self.new(code : SetupErrorCode, message : String) : SetupFailure
        SetupFailure.new(code, message)
      end

      def self.from_report(report : SetupErrorReport) : SetupFailure
        SetupFailure.new(report.code, report.message)
      end

      def self.metric_message(failure : SetupFailure) : String
        failure.metric_message
      end

      def self.failure(code : SetupErrorCode, message : String) : SetupFailure
        SetupFailure.new(code, message)
      end

      def self.extract_failure(error : Exception) : SetupFailure?
        error.as?(SetupFailure)
      end

      def self.run_setup_refresh(
        policy : String,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String),
        home_dir : String = sandbox_home,
      ) : Nil
        {% unless flag?(:win32) %}
          raise "Windows sandbox is only available on Windows"
        {% end %}

        run_elevated_setup(
          policy,
          policy_cwd,
          command_cwd,
          env_map,
          home_dir
        )
      end

      def self.run_setup_refresh_with_extra_read_roots(
        policy : String,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String),
        extra_read_roots : Array(String),
        home_dir : String = sandbox_home,
      ) : Nil
        {% unless flag?(:win32) %}
          raise "Windows sandbox is only available on Windows"
        {% end %}

        run_elevated_setup(
          policy,
          policy_cwd,
          command_cwd,
          env_map,
          home_dir,
          read_roots_override: extra_read_roots,
          write_roots_override: [] of String
        )
      end

      def self.run_setup_refresh_with_extra_read_roots(
        policy : String,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String),
        home_dir : String,
        extra_read_roots : Array(String),
      ) : Nil
        run_setup_refresh_with_extra_read_roots(
          policy,
          policy_cwd,
          command_cwd,
          env_map,
          extra_read_roots,
          home_dir
        )
      end

      def self.run_elevated_setup(
        policy : String,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String),
        home_dir : String = sandbox_home,
        read_roots_override : Array(String)? = nil,
        write_roots_override : Array(String)? = nil,
      ) : Nil
        {% unless flag?(:win32) %}
          _ = policy
          _ = policy_cwd
          _ = command_cwd
          _ = env_map
          _ = home_dir
          _ = read_roots_override
          _ = write_roots_override
          raise "Windows sandbox is only available on Windows"
        {% end %}

        raise "Windows restricted-token backend is required; insecure fallback disabled" unless windows_insecure_fallback_enabled?

        policy_obj = parse_policy(policy)
        Dir.mkdir_p(sandbox_dir(home_dir))
        Dir.mkdir_p(sandbox_secrets_dir(home_dir))
        clear_setup_error_report(home_dir)
        provision_sandbox_users

        users = SandboxUsersFile.new(
          offline: SandboxUserRecord.new(offline_username, protect("offline")),
          online: SandboxUserRecord.new(online_username, protect("online"))
        )
        File.write(sandbox_users_path(home_dir), users.to_json)

        if roots = effective_read_roots(read_roots_override, policy_obj, policy_cwd, command_cwd, env_map, home_dir)
          File.write(
            File.join(sandbox_dir(home_dir), "read_roots.json"),
            stable_path_list(roots).to_json
          )
        end
        if roots = effective_write_roots(write_roots_override, policy_obj, policy_cwd, command_cwd, env_map)
          File.write(
            File.join(sandbox_dir(home_dir), "write_roots.json"),
            stable_path_list(roots).to_json
          )
        end

        marker = SetupMarker.new
        File.write(setup_marker_path(home_dir), marker.to_json)

        apply_world_writable_scan_and_denies(
          command_cwd,
          env_map,
          policy,
          home_dir
        )
        hide_current_user_profile_dir(home_dir)
        hide_newly_created_users(home_dir: home_dir)
      rescue error
        report = setup_report_for_error(error)
        write_setup_error_report(report, home_dir)
        raise error
      end

      def self.version_matches(version : Int32) : Bool
        version == SETUP_VERSION
      end

      def self.setup_main_win_main(request_path : String) : String
        read_request_file(request_path)
      end

      def self.format_last_error(error_code : Int32) : String
        "Windows error #{error_code}"
      end

      def self.quote_windows_arg(arg : String) : String
        needs_quotes = arg.empty? || arg.each_char.any? { |char| {' ', '\t', '\n', '\r', '"'}.includes?(char) }
        return arg unless needs_quotes

        quoted = String::Builder.new(arg.bytesize + 2)
        quoted << '"'
        backslashes = 0

        arg.each_char do |char|
          case char
          when '\\'
            backslashes += 1
          when '"'
            quoted << "\\" * (backslashes * 2 + 1)
            quoted << '"'
            backslashes = 0
          else
            if backslashes > 0
              quoted << "\\" * backslashes
              backslashes = 0
            end
            quoted << char
          end
        end

        if backslashes > 0
          quoted << "\\" * (backslashes * 2)
        end
        quoted << '"'
        quoted.to_s
      end

      def self.string_from_sid_bytes(bytes : Bytes) : String
        sid_bytes_to_psid(bytes)
      end

      def self.command_cwd_root?(cwd : String) : Bool
        expanded = canonicalize_path(cwd)
        expanded == "/" || expanded.matches?(/^[a-zA-Z]:[\\\/]?$/)
      end

      # ameba:disable Naming/PredicateName
      def self.is_command_cwd_root(cwd : String) : Bool
        command_cwd_root?(cwd)
      end

      # ameba:enable Naming/PredicateName

      def self.profile_read_roots(user_profile : String) : Array(String)
        return [user_profile] unless Dir.exists?(user_profile)

        roots = [] of String
        Dir.each_child(user_profile) do |name|
          next if USERPROFILE_READ_ROOT_EXCLUSIONS.any? { |excluded| excluded.compare(name, case_insensitive: true) == 0 }
          roots << File.join(user_profile, name)
        end
        roots
      rescue
        [user_profile]
      end

      def self.gather_read_roots(
        command_cwd : String,
        home_dir : String = sandbox_home,
        writable_roots : Array(String) = [] of String,
      ) : Array(String)
        helper_dir = helper_bin_dir(home_dir)
        Dir.mkdir_p(helper_dir)

        roots = [] of String
        roots << helper_dir
        roots << command_cwd
        roots.concat(writable_roots)

        seen = Set(String).new
        out = [] of String
        roots.each do |root|
          canonical = canonicalize_path(root)
          next unless path_exists?(canonical)
          next unless seen.add?(canonical)
          out << canonical
        end
        out
      end

      private def self.unique_push_candidate(
        candidates : Array(String),
        seen : Set(String),
        path : String,
      ) : Nil
        canonical = canonicalize_path(path)
        return unless path_exists?(canonical)
        return unless seen.add?(canonical)
        candidates << canonical
      end

      private def self.path_exists?(path : String) : Bool
        File.exists?(path) || Dir.exists?(path)
      end

      private def self.absolute_path_like?(path : String) : Bool
        return true if Path[path].absolute?
        path.starts_with?("/") || path.matches?(/^[a-zA-Z]:[\\\/]/)
      end

      private def self.windows_insecure_fallback_enabled? : Bool
        ENV[WINDOWS_INSECURE_FALLBACK_ENV]? == "1"
      end

      private def self.setup_report_for_error(error : Exception) : SetupErrorReport
        if failure = extract_failure(error)
          SetupErrorReport.new(failure.code, failure.message || "setup failure")
        else
          SetupErrorReport.new(
            SetupErrorCode::HelperUnknownError,
            error.message || "unknown setup failure"
          )
        end
      end

      private def self.stable_path_list(paths : Array(String)) : Array(String)
        seen = Set(String).new
        normalized = [] of String

        paths.each do |path|
          canonical = canonicalize_path(path)
          next unless path_exists?(canonical)
          key = canonical_path_key(canonical)
          next unless seen.add?(key)
          normalized << canonical
        end

        normalized.sort_by { |path| canonical_path_key(path) }
      end

      private def self.command_indicates_existing?(stdout : String, stderr : String) : Bool
        message = "#{stdout}\n#{stderr}".downcase
        message.includes?("already exists") ||
          message.includes?("already a member") ||
          message.includes?("already in group")
      end

      private def self.run_command_capture(program : String, args : Array(String)) : Tuple(Process::Status, String, String)
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run(
          program,
          args: args,
          output: stdout,
          error: stderr
        )
        {status, stdout.to_s, stderr.to_s}
      end

      private def self.powershell_single_quote_escape(value : String) : String
        value.gsub("'", "''")
      end

      private def self.effective_read_roots(
        read_roots_override : Array(String)?,
        policy : Policy,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String),
        home_dir : String,
      ) : Array(String)?
        if read_roots_override
          return stable_path_list(read_roots_override)
        end
        return unless policy.kind.workspace_write?

        allow_deny_paths = compute_allow_paths(policy, policy_cwd, command_cwd, env_map)
        gather_read_roots(command_cwd, home_dir, allow_deny_paths.allow.to_a)
      end

      private def self.effective_write_roots(
        write_roots_override : Array(String)?,
        policy : Policy,
        policy_cwd : String,
        command_cwd : String,
        env_map : Hash(String, String),
      ) : Array(String)?
        if write_roots_override
          return stable_path_list(write_roots_override)
        end
        return unless policy.kind.workspace_write?

        compute_allow_paths(policy, policy_cwd, command_cwd, env_map).allow.to_a
      end

      private def self.parse_policy_json_object(parsed : Hash(String, JSON::Any)) : Policy
        kind = parsed["kind"]?.try(&.as_s?)
        raise "Unsupported Windows sandbox policy payload" unless kind

        case kind
        when "ReadOnly"
          Policy.read_only
        when "WorkspaceWrite"
          parse_workspace_write_policy(parsed)
        when "DangerFullAccess", "ExternalSandbox"
          raise "DangerFullAccess and ExternalSandbox are not supported for sandboxing"
        else
          raise "Unsupported Windows sandbox policy payload"
        end
      end

      private def self.parse_workspace_write_policy(parsed : Hash(String, JSON::Any)) : Policy
        network_access = parsed["network_access"]?.try(&.as_bool?) || false
        writable_roots = parsed["writable_roots"]?.try(&.as_a.map(&.as_s)) || [] of String
        exclude_tmpdir_env_var = parsed["exclude_tmpdir_env_var"]?.try(&.as_bool?) || false
        exclude_slash_tmp = parsed["exclude_slash_tmp"]?.try(&.as_bool?) || false
        Policy.workspace_write(
          network_access: network_access,
          writable_roots: writable_roots,
          exclude_tmpdir_env_var: exclude_tmpdir_env_var,
          exclude_slash_tmp: exclude_slash_tmp
        )
      end

      private def self.path_within_root?(canonical_path : String, canonical_root : String) : Bool
        return true if canonical_path == canonical_root
        root_with_sep = canonical_root.ends_with?("/") ? canonical_root : "#{canonical_root}/"
        canonical_path.starts_with?(root_with_sep)
      end

      private def self.append_unique_metadata_entry(path : String, value : String) : Nil
        Dir.mkdir_p(File.dirname(path))
        entries = if File.exists?(path)
                    Array(String).from_json(File.read(path))
                  else
                    [] of String
                  end
        return if entries.includes?(value)
        entries << value
        File.write(path, entries.to_json)
      rescue
        nil
      end

      private def self.world_writable?(path : String) : Bool
        info = File.info(path)
        info.permissions.other_write?
      rescue
        false
      end

      private def self.skip_audit_dir?(path : String) : Bool
        normalized = path.downcase.gsub('\\', '/')
        AUDIT_SKIP_DIR_SUFFIXES.any? { |suffix| normalized.ends_with?(suffix) }
      end

      private def self.harden_write_permissions(path : String) : Nil
        info = File.info(path)
        permissions = info.permissions
        return unless permissions.other_write?

        hardened = permissions & ~File::Permissions::OtherWrite
        File.chmod(path, hardened)
      rescue
        nil
      end

      private def self.scan_cwd_children_for_world_writable(
        cwd : String,
        start_time : Time::Instant,
        checked : Int32,
        seen : Set(String),
        flagged : Array(String),
      ) : Int32
        return checked unless Dir.exists?(cwd)

        Dir.each_child(cwd) do |entry|
          break if audit_limit_reached?(start_time, checked)
          path = File.join(cwd, entry)
          next unless Dir.exists?(path)
          next if File.symlink?(path)
          checked = scan_world_writable_path(path, start_time, checked, seen, flagged)
        end
        checked
      end

      private def self.scan_candidate_roots_for_world_writable(
        cwd : String,
        env_map : Hash(String, String),
        start_time : Time::Instant,
        checked : Int32,
        seen : Set(String),
        flagged : Array(String),
      ) : Int32
        gather_candidates(cwd, env_map).each do |root|
          break if audit_limit_reached?(start_time, checked)

          checked = scan_world_writable_path(root, start_time, checked, seen, flagged)
          next unless Dir.exists?(root)

          child_count = 0
          Dir.each_child(root) do |entry|
            break if child_count >= MAX_ITEMS_PER_DIR
            break if audit_limit_reached?(start_time, checked)

            path = File.join(root, entry)
            child_count += 1
            next unless Dir.exists?(path)
            next if File.symlink?(path)
            next if skip_audit_dir?(path)
            checked = scan_world_writable_path(path, start_time, checked, seen, flagged)
          end
        end
        checked
      end

      private def self.scan_world_writable_path(
        path : String,
        start_time : Time::Instant,
        checked : Int32,
        seen : Set(String),
        flagged : Array(String),
      ) : Int32
        return checked if audit_limit_reached?(start_time, checked)

        checked += 1
        return checked unless world_writable?(path)

        key = canonical_path_key(path)
        return checked unless seen.add?(key)
        flagged << canonicalize_path(path)
        checked
      end

      private def self.audit_limit_reached?(start_time : Time::Instant, checked : Int32) : Bool
        checked >= MAX_CHECKED_LIMIT || (Time.instant - start_time) > AUDIT_TIME_LIMIT
      end

      private def self.log_file_path(base_dir : String?) : String?
        return unless base_dir
        return unless Dir.exists?(base_dir)
        File.join(base_dir, LOG_FILE_NAME)
      end

      private def self.append_line(line : String, base_dir : String?) : Nil
        path = log_file_path(base_dir)
        return unless path
        File.open(path, "a") do |file|
          file.puts(line)
        end
      rescue
        nil
      end

      private def self.exe_label : String
        exe = Process.executable_path
        return "proc" unless exe
        File.basename(exe)
      rescue
        "proc"
      end
    end
  end
end
