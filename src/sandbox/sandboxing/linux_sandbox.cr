require "file_utils"
require "json"
require "uri"

module Sandbox
  module Sandboxing
    module LinuxSandbox
      PROXY_ENV_KEYS = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "FTP_PROXY",
        "YARN_HTTP_PROXY",
        "YARN_HTTPS_PROXY",
        "NPM_CONFIG_HTTP_PROXY",
        "NPM_CONFIG_HTTPS_PROXY",
        "NPM_CONFIG_PROXY",
        "BUNDLE_HTTP_PROXY",
        "BUNDLE_HTTPS_PROXY",
        "PIP_PROXY",
        "DOCKER_HTTP_PROXY",
        "DOCKER_HTTPS_PROXY",
      ]

      PROXY_SOCKET_DIR_PREFIX           = "codex-linux-sandbox-proxy-"
      LINUX_PLATFORM_DEFAULT_READ_ROOTS = [
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/lib",
        "/lib64",
        "/nix/store",
        "/run/current-system/sw",
      ]

      struct PlannedProxyRoute
        getter env_key : String
        getter endpoint : String

        def initialize(@env_key : String, @endpoint : String)
        end
      end

      struct ProxyRoutePlan
        getter routes : Array(PlannedProxyRoute)
        getter? has_proxy_config : Bool

        def initialize(@routes : Array(PlannedProxyRoute), @has_proxy_config : Bool)
        end
      end

      struct ProxyRouteEntry
        include JSON::Serializable

        getter env_key : String
        getter uds_path : String

        def initialize(@env_key : String, @uds_path : String)
        end
      end

      struct ProxyRouteSpec
        include JSON::Serializable

        getter routes : Array(ProxyRouteEntry)

        def initialize(@routes : Array(ProxyRouteEntry))
        end
      end

      enum LegacySandboxPolicy
        DangerFullAccess
        ReadOnly
        WorkspaceWrite
        ExternalSandbox
      end

      enum BwrapNetworkMode
        FullAccess
        Isolated
        ProxyOnly
      end

      enum SeccompNetworkMode
        Restricted
        ProxyRouted
      end

      struct EffectiveSandboxPolicies
        getter sandbox_policy : LegacySandboxPolicy
        getter file_system_sandbox_policy : FileSystemSandboxPolicy
        getter network_sandbox_policy : NetworkSandboxPolicy

        def initialize(
          @sandbox_policy : LegacySandboxPolicy,
          @file_system_sandbox_policy : FileSystemSandboxPolicy,
          @network_sandbox_policy : NetworkSandboxPolicy,
        )
        end
      end

      struct LandlockCommand
        getter sandbox_policy_cwd : String
        getter? use_bwrap_sandbox : Bool
        getter? apply_seccomp_then_exec : Bool
        getter? allow_network_for_proxy : Bool
        getter proxy_route_spec : String?
        getter? no_proc : Bool
        getter command : Array(String)

        def initialize(
          @sandbox_policy_cwd : String = Dir.current,
          @use_bwrap_sandbox : Bool = false,
          @apply_seccomp_then_exec : Bool = false,
          @allow_network_for_proxy : Bool = false,
          @proxy_route_spec : String? = nil,
          @no_proc : Bool = false,
          @command : Array(String) = [] of String,
        )
        end
      end

      def self.create_command_args(
        command : Array(String),
        use_bwrap : Bool,
      ) : Array(String)
        args = [] of String
        args << "--use-bwrap" if use_bwrap
        args << "--"
        args.concat(command)
        args
      end

      def self.run_main(
        landlock_command : LandlockCommand,
        file_system_policy : FileSystemSandboxPolicy,
        network_policy : NetworkSandboxPolicy,
        current_exe : String = "codex-linux-sandbox",
      ) : Array(String)
        raise "No command specified to execute." if landlock_command.command.empty?

        ensure_inner_stage_mode_is_valid(
          landlock_command.apply_seccomp_then_exec?,
          landlock_command.use_bwrap_sandbox?
        )

        if landlock_command.apply_seccomp_then_exec?
          if landlock_command.allow_network_for_proxy? && landlock_command.proxy_route_spec.nil?
            raise "managed proxy mode requires --proxy-route-spec"
          end
          return landlock_command.command
        end

        if file_system_policy.full_disk_write_access? && !landlock_command.allow_network_for_proxy?
          return landlock_command.command
        end

        if landlock_command.use_bwrap_sandbox?
          return build_inner_seccomp_command(
            landlock_command,
            network_policy,
            current_exe
          )
        end

        landlock_command.command
      end

      def self.resolve_sandbox_policies(
        sandbox_policy_cwd : String,
        sandbox_policy : LegacySandboxPolicy?,
        file_system_sandbox_policy : FileSystemSandboxPolicy?,
        network_sandbox_policy : NetworkSandboxPolicy?,
      ) : EffectiveSandboxPolicies
        _ = sandbox_policy_cwd
        split_policies = if file_system_sandbox_policy && network_sandbox_policy
                           {file_system_sandbox_policy, network_sandbox_policy}
                         elsif file_system_sandbox_policy.nil? && network_sandbox_policy.nil?
                           nil
                         else
                           raise "file-system and network sandbox policies must be provided together"
                         end

        if sandbox_policy && split_policies
          EffectiveSandboxPolicies.new(
            sandbox_policy: sandbox_policy,
            file_system_sandbox_policy: split_policies[0],
            network_sandbox_policy: split_policies[1]
          )
        elsif sandbox_policy
          EffectiveSandboxPolicies.new(
            sandbox_policy: sandbox_policy,
            file_system_sandbox_policy: file_system_policy_from_legacy(sandbox_policy),
            network_sandbox_policy: network_policy_from_legacy(sandbox_policy)
          )
        elsif split_policies
          legacy_policy = legacy_policy_from_split(
            split_policies[0],
            split_policies[1]
          )
          EffectiveSandboxPolicies.new(
            sandbox_policy: legacy_policy,
            file_system_sandbox_policy: split_policies[0],
            network_sandbox_policy: split_policies[1]
          )
        else
          raise "missing sandbox policy configuration"
        end
      end

      def self.ensure_inner_stage_mode_is_valid(
        apply_seccomp_then_exec : Bool,
        use_bwrap_sandbox : Bool,
      ) : Nil
        if apply_seccomp_then_exec && !use_bwrap_sandbox
          raise "--apply-seccomp-then-exec requires --use-bwrap-sandbox"
        end
      end

      def self.bwrap_network_mode(
        network_policy : NetworkSandboxPolicy,
        allow_network_for_proxy : Bool,
      ) : BwrapNetworkMode
        if allow_network_for_proxy
          BwrapNetworkMode::ProxyOnly
        elsif network_policy.enabled?
          BwrapNetworkMode::FullAccess
        else
          BwrapNetworkMode::Isolated
        end
      end

      def self.should_install_network_seccomp(
        network_policy : NetworkSandboxPolicy,
        allow_network_for_proxy : Bool,
      ) : Bool
        !network_policy.enabled? || allow_network_for_proxy
      end

      def self.network_seccomp_mode(
        network_policy : NetworkSandboxPolicy,
        allow_network_for_proxy : Bool,
        proxy_routed_network : Bool,
      ) : SeccompNetworkMode?
        if should_install_network_seccomp(network_policy, allow_network_for_proxy)
          proxy_routed_network ? SeccompNetworkMode::ProxyRouted : SeccompNetworkMode::Restricted
        end
      end

      def self.proc_mount_failure?(stderr : String) : Bool
        stderr.includes?("Can't mount proc") &&
          stderr.includes?("/newroot/proc") &&
          (
            stderr.includes?("Invalid argument") ||
              stderr.includes?("Operation not permitted") ||
              stderr.includes?("Permission denied")
          )
      end

      def self.create_bwrap_command_args(
        command : Array(String),
        file_system_policy : FileSystemSandboxPolicy,
        network_mode : BwrapNetworkMode,
        mount_proc : Bool = true,
      ) : Array(String)
        if file_system_policy.full_disk_write_access? && network_mode.full_access?
          return command
        end

        args = [
          "--new-session",
          "--die-with-parent",
          "--bind",
          "/",
          "/",
          "--unshare-user",
          "--unshare-pid",
        ]
        args << "--unshare-net" unless network_mode.full_access?
        if mount_proc
          args << "--proc"
          args << "/proc"
        end
        args << "--"
        args.concat(command)
        args
      end

      def self.create_bwrap_filesystem_args(
        readable_roots : Array(String),
        writable_roots : Array(String),
        unreadable_roots : Array(String),
        full_disk_read_access : Bool,
        include_platform_defaults : Bool = false,
      ) : Array(String)
        args = if full_disk_read_access || readable_roots.includes?("/")
                 ["--ro-bind", "/", "/", "--dev", "/dev"]
               else
                 ["--tmpfs", "/", "--dev", "/dev"]
               end

        unless full_disk_read_access || readable_roots.includes?("/")
          roots = readable_roots.dup
          if include_platform_defaults
            LINUX_PLATFORM_DEFAULT_READ_ROOTS.each do |root|
              roots << root if path_exists?(root)
            end
          end
          roots.uniq!
          roots.each do |root|
            next unless path_exists?(root)
            args << "--ro-bind"
            args << root
            args << root
          end
        end

        writable_roots.each do |root|
          next unless path_exists?(root)
          args << "--bind"
          args << root
          args << root
        end

        # Re-apply unreadable carveouts last so they win over baseline read/write binds.
        unreadable_roots.each do |root|
          next unless path_exists?(root)
          args << "--tmpfs"
          args << root
        end

        args
      end

      def self.build_inner_seccomp_command(
        landlock_command : LandlockCommand,
        network_policy : NetworkSandboxPolicy,
        current_exe : String,
      ) : Array(String)
        inner = [
          current_exe,
          "--sandbox-policy-cwd",
          landlock_command.sandbox_policy_cwd,
          "--sandbox-policy",
          "{}",
          "--file-system-sandbox-policy",
          "{}",
          "--network-sandbox-policy",
          network_policy.enabled? ? "\"enabled\"" : "\"restricted\"",
        ]

        if landlock_command.use_bwrap_sandbox?
          inner << "--use-bwrap-sandbox"
        end
        inner << "--apply-seccomp-then-exec"

        if landlock_command.allow_network_for_proxy?
          inner << "--allow-network-for-proxy"
          spec = landlock_command.proxy_route_spec ||
                 raise("managed proxy mode requires --proxy-route-spec")
          inner << "--proxy-route-spec"
          inner << spec
        end

        inner << "--"
        inner.concat(landlock_command.command)
        inner
      end

      private def self.file_system_policy_from_legacy(
        sandbox_policy : LegacySandboxPolicy,
      ) : FileSystemSandboxPolicy
        case sandbox_policy
        in .danger_full_access?
          FileSystemSandboxPolicy.unrestricted
        in .external_sandbox?
          FileSystemSandboxPolicy.external
        in .workspace_write?
          FileSystemSandboxPolicy.restricted(full_disk_write_access: true)
        in .read_only?
          FileSystemSandboxPolicy.restricted(full_disk_write_access: false)
        end
      end

      private def self.network_policy_from_legacy(
        sandbox_policy : LegacySandboxPolicy,
      ) : NetworkSandboxPolicy
        case sandbox_policy
        in .danger_full_access?
          NetworkSandboxPolicy::Enabled
        in .external_sandbox?
          NetworkSandboxPolicy::Restricted
        in .workspace_write?, .read_only?
          NetworkSandboxPolicy::Restricted
        end
      end

      private def self.legacy_policy_from_split(
        file_system_sandbox_policy : FileSystemSandboxPolicy,
        network_sandbox_policy : NetworkSandboxPolicy,
      ) : LegacySandboxPolicy
        if file_system_sandbox_policy.kind.external_sandbox?
          LegacySandboxPolicy::ExternalSandbox
        elsif file_system_sandbox_policy.kind.unrestricted? && network_sandbox_policy.enabled?
          LegacySandboxPolicy::DangerFullAccess
        elsif file_system_sandbox_policy.full_disk_write_access?
          LegacySandboxPolicy::WorkspaceWrite
        else
          LegacySandboxPolicy::ReadOnly
        end
      end

      def self.proxy_env_key?(key : String) : Bool
        PROXY_ENV_KEYS.includes?(key.upcase)
      end

      def self.default_proxy_port(scheme : String) : Int32
        downcased = scheme.downcase
        if downcased == "https"
          443
        elsif {"socks5", "socks5h", "socks4", "socks4a"}.includes?(downcased)
          1080
        else
          80
        end
      end

      def self.parse_loopback_proxy_endpoint(proxy_url : String) : String?
        had_scheme = proxy_url.includes?("://")
        candidate = had_scheme ? proxy_url : "http://#{proxy_url}"
        parsed = URI.parse(candidate)
        parsed.host.try do |host|
          next unless loopback_host?(host)
          port = parsed.port || default_proxy_port(parsed.scheme || "http")
          next unless port > 0

          "#{host.downcase == "localhost" ? "127.0.0.1" : host}:#{port}"
        end
      rescue
        nil
      end

      def self.plan_proxy_routes(env : Hash(String, String)) : ProxyRoutePlan
        routes = [] of PlannedProxyRoute
        has_proxy_config = false

        env.each do |key, value|
          next unless proxy_env_key?(key)
          trimmed = value.strip
          next if trimmed.empty?

          has_proxy_config = true
          endpoint = parse_loopback_proxy_endpoint(trimmed)
          next unless endpoint
          routes << PlannedProxyRoute.new(key, endpoint)
        end

        routes.sort_by!(&.env_key)
        ProxyRoutePlan.new(routes, has_proxy_config)
      end

      def self.rewrite_proxy_env_value(proxy_url : String, local_port : Int32) : String?
        had_scheme = proxy_url.includes?("://")
        candidate = had_scheme ? proxy_url : "http://#{proxy_url}"
        parsed = URI.parse(candidate)
        rewrite_parsed_proxy_env_value(parsed, proxy_url, local_port, had_scheme)
      rescue
        nil
      end

      def self.parse_proxy_socket_dir_owner_pid(file_name : String) : Int32?
        suffix = file_name.sub(/^#{Regex.escape(PROXY_SOCKET_DIR_PREFIX)}/, "")
        unless suffix == file_name
          suffix.split('-', 2).first?.try do |pid_raw|
            pid_raw.to_i?.try { |pid| pid > 0 ? pid : nil }
          end
        end
      end

      def self.cleanup_proxy_socket_dir(socket_dir : String) : Nil
        FileUtils.rm_rf(socket_dir)
      end

      def self.serialize_proxy_route_spec(spec : ProxyRouteSpec) : String
        spec.to_json
      end

      def self.cleanup_stale_proxy_socket_dirs_in(temp_dir : String) : Nil
        Dir.each_child(temp_dir) do |entry|
          path = File.join(temp_dir, entry)
          next unless Dir.exists?(path)
          owner_pid = parse_proxy_socket_dir_owner_pid(entry)
          next unless owner_pid
          # In Crystal port scaffolding, treat all discovered owner pid dirs as stale.
          cleanup_proxy_socket_dir(path)
        end
      end

      private def self.loopback_host?(host : String) : Bool
        normalized = host.downcase
        normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
      end

      private def self.rewrite_parsed_proxy_env_value(
        parsed : URI,
        original : String,
        local_port : Int32,
        had_scheme : Bool,
      ) : String?
        parsed.host.try do
          scheme = parsed.scheme || "http"
          rewritten = "#{scheme}://#{proxy_userinfo(parsed)}127.0.0.1:#{local_port}#{parsed.path || ""}#{parsed.query ? "?#{parsed.query}" : ""}#{parsed.fragment ? "##{parsed.fragment}" : ""}"
          rewritten = rewritten.sub(/^http:\/\//, "") unless had_scheme
          trim_redundant_trailing_slash(rewritten, original)
        end
      end

      private def self.proxy_userinfo(parsed : URI) : String
        if parsed.user && parsed.password
          "#{parsed.user}:#{parsed.password}@"
        elsif parsed.user
          "#{parsed.user}@"
        else
          ""
        end
      end

      private def self.trim_redundant_trailing_slash(rewritten : String, original : String) : String
        if !original.ends_with?('/') &&
           !original.includes?('?') &&
           !original.includes?('#') &&
           rewritten.ends_with?('/')
          rewritten[0...-1]
        else
          rewritten
        end
      end

      private def self.path_exists?(path : String) : Bool
        File.exists?(path) || Dir.exists?(path)
      end
    end
  end
end
