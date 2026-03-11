require "uri"

module Sandbox
  module Sandboxing
    module MacosSeatbelt
      EXECUTABLE         = "/usr/bin/sandbox-exec"
      PROXY_URL_ENV_KEYS = [
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
      MACOS_SEATBELT_BASE_POLICY = [
        "(version 1)",
        "(deny default)",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow signal (target same-sandbox))",
        "(allow process-info* (target same-sandbox))",
        "(allow file-write-data",
        "  (require-all",
        "    (path \"/dev/null\")",
        "    (vnode-type CHARACTER-DEVICE)))",
        "(allow sysctl-read",
        "  (sysctl-name \"machdep.cpu.brand_string\")",
        "  (sysctl-name \"hw.model\"))",
      ].join('\n')
      MACOS_SEATBELT_NETWORK_POLICY = [
        "; allow only safe AF_SYSTEM sockets used for local platform services.",
        "(allow system-socket",
        "  (require-all",
        "    (socket-domain AF_SYSTEM)",
        "    (socket-protocol 2)",
        "  )",
        ")",
        "",
        "(allow mach-lookup",
        "    (global-name \"com.apple.bsd.dirhelper\")",
        "    (global-name \"com.apple.system.opendirectoryd.membership\")",
        "    (global-name \"com.apple.SecurityServer\")",
        "    (global-name \"com.apple.networkd\")",
        "    (global-name \"com.apple.ocspd\")",
        "    (global-name \"com.apple.trustd.agent\")",
        "    (global-name \"com.apple.SystemConfiguration.DNSConfiguration\")",
        "    (global-name \"com.apple.SystemConfiguration.configd\")",
        ")",
        "",
        "(allow sysctl-read",
        "  (sysctl-name-regex #\"^net.routetable\")",
        ")",
        "",
        "(allow file-write*",
        "  (subpath (param \"DARWIN_USER_CACHE_DIR\"))",
        ")",
      ].join('\n')

      enum UnixDomainSocketPolicyKind
        AllowAll
        Restricted
      end

      struct ProxyPolicyInputs
        getter ports : Array(Int32)
        getter? has_proxy_config : Bool
        getter? allow_local_binding : Bool
        getter unix_domain_socket_policy_kind : UnixDomainSocketPolicyKind
        getter allowed_unix_socket_paths : Array(String)

        def initialize(
          @ports : Array(Int32) = [] of Int32,
          @has_proxy_config : Bool = false,
          @allow_local_binding : Bool = false,
          @unix_domain_socket_policy_kind : UnixDomainSocketPolicyKind = UnixDomainSocketPolicyKind::Restricted,
          @allowed_unix_socket_paths : Array(String) = [] of String,
        )
        end
      end

      def self.create_command_args(
        command : Array(String),
        file_system_policy : FileSystemSandboxPolicy,
        network_policy : NetworkSandboxPolicy,
        extensions : MacosSeatbeltProfileExtensions? = nil,
      ) : Array(String)
        profile = profile_for(file_system_policy, network_policy, extensions)
        ["-p", profile] + command
      end

      # Keep the policy intentionally small for bootstrap parity.
      def self.profile_for(
        file_system_policy : FileSystemSandboxPolicy,
        network_policy : NetworkSandboxPolicy,
        extensions : MacosSeatbeltProfileExtensions? = nil,
      ) : String
        statements = [MACOS_SEATBELT_BASE_POLICY, "(allow file-read*)"]

        if file_system_policy.kind.unrestricted?
          statements << "(allow file-write*)"
        end

        dynamic_network = dynamic_network_policy(
          network_policy,
          false,
          ProxyPolicyInputs.new
        )
        unless dynamic_network.empty?
          statements << dynamic_network
        end

        extension_policy = SeatbeltPermissions.build_seatbelt_extensions(
          extensions || MacosSeatbeltProfileExtensions.default
        )
        unless extension_policy.policy.empty?
          statements << extension_policy.policy
        end

        statements.join(" ")
      end

      def self.proxy_scheme_default_port(scheme : String) : Int32
        case scheme.downcase
        when "https"
          443
        when "socks5", "socks5h", "socks4", "socks4a"
          1080
        else
          80
        end
      end

      def self.proxy_loopback_ports_from_env(env : Hash(String, String)) : Array(Int32)
        ports = [] of Int32
        PROXY_URL_ENV_KEYS.each do |key|
          proxy_url = env[key]?
          next unless proxy_url
          trimmed = proxy_url.strip
          next if trimmed.empty?

          candidate = trimmed.includes?("://") ? trimmed : "http://#{trimmed}"
          parsed = URI.parse(candidate)
          host = parsed.host
          next unless host && loopback_host?(host)
          port = parsed.port || proxy_scheme_default_port(parsed.scheme || "http")
          ports << port
        rescue
          next
        end

        ports.uniq!
        ports.sort!
        ports
      end

      def self.normalize_path_for_sandbox(path : String) : String?
        if path.starts_with?("/")
          File.expand_path(path)
        end
      end

      def self.unix_socket_path_param_key(index : Int32) : String
        "UNIX_SOCKET_PATH_#{index}"
      end

      def self.unix_socket_dir_params(proxy : ProxyPolicyInputs) : Array({String, String})
        return [] of {String, String} unless proxy.unix_domain_socket_policy_kind.restricted?

        normalized = proxy.allowed_unix_socket_paths.compact_map do |socket_path|
          normalize_path_for_sandbox(socket_path)
        end
        normalized.uniq!
        normalized.sort!

        normalized.each_with_index.map do |path, index|
          {unix_socket_path_param_key(index), path}
        end.to_a
      end

      def self.unix_socket_policy(proxy : ProxyPolicyInputs) : String
        params = unix_socket_dir_params(proxy)
        has_unix_socket_access = proxy.unix_domain_socket_policy_kind.allow_all? || !params.empty?
        return "" unless has_unix_socket_access

        policy = "(allow system-socket (socket-domain AF_UNIX))\n"
        if proxy.unix_domain_socket_policy_kind.allow_all?
          policy += "(allow network-bind (local unix-socket))\n"
          policy += "(allow network-outbound (remote unix-socket))\n"
          return policy
        end

        params.each do |(key, _)|
          policy += %( (allow network-bind (local unix-socket (subpath (param "#{key}"))))\n).lstrip
          policy += %( (allow network-outbound (remote unix-socket (subpath (param "#{key}"))))\n).lstrip
        end
        policy
      end

      def self.protected_git_codex_subpaths(root : String) : Array(String)
        base = normalize_path_for_sandbox(root) || return [] of String
        entries = [] of String

        dot_git = File.join(base, ".git")
        if File.exists?(dot_git) || Dir.exists?(dot_git)
          normalized_git = normalize_path_for_sandbox(dot_git)
          entries << normalized_git if normalized_git

          if File.file?(dot_git)
            pointer_target = git_pointer_target(dot_git, base)
            entries << pointer_target if pointer_target
          end
        end

        dot_codex = File.join(base, ".codex")
        if File.exists?(dot_codex) || Dir.exists?(dot_codex)
          normalized_codex = normalize_path_for_sandbox(dot_codex)
          entries << normalized_codex if normalized_codex
        end

        entries.uniq!
        entries.sort!
        entries
      end

      def self.unreadable_root_carveout_policy(unreadable_roots : Array(String)) : String
        normalized = unreadable_roots.compact_map { |path| normalize_path_for_sandbox(path) }
        normalized.uniq!
        normalized.sort!
        return "" if normalized.empty?

        clauses = normalized.map do |root|
          %( (require-not (subpath "#{root}")) )
        end
        "(require-all#{clauses.join})"
      end

      def self.legacy_workspace_write_nested_readable_root_stays_writable?(
        writable_root : String,
        readable_root : String,
      ) : Bool
        writable = normalize_path_for_sandbox(writable_root) || return false
        readable = normalize_path_for_sandbox(readable_root) || return false
        readable.starts_with?("#{writable}/")
      end

      def self.dynamic_network_policy(
        network_policy : NetworkSandboxPolicy,
        enforce_managed_network : Bool,
        proxy : ProxyPolicyInputs,
      ) : String
        should_use_restricted_network_policy =
          !proxy.ports.empty? || proxy.has_proxy_config? || enforce_managed_network
        if should_use_restricted_network_policy
          policy = ""
          if proxy.allow_local_binding?
            policy += %(; allow loopback local binding and loopback traffic\n)
            policy += %((allow network-bind (local ip "localhost:*"))\n)
            policy += %((allow network-inbound (local ip "localhost:*"))\n)
            policy += %((allow network-outbound (remote ip "localhost:*"))\n)
          end
          proxy.ports.each do |port|
            policy += %((allow network-outbound (remote ip "localhost:#{port}"))\n)
          end
          unix_socket = unix_socket_policy(proxy)
          unless unix_socket.empty?
            policy += %(; allow unix domain sockets for local IPC\n)
            policy += unix_socket
          end
          return "#{policy}#{MACOS_SEATBELT_NETWORK_POLICY}"
        end

        if proxy.has_proxy_config? || enforce_managed_network
          # Fail closed: keep network denied when managed requirements are active
          # but there are no concrete loopback endpoints to permit.
          return ""
        end

        if network_policy.enabled?
          %( (allow network-outbound)\n(allow network-inbound)\n).lstrip + MACOS_SEATBELT_NETWORK_POLICY
        else
          ""
        end
      end

      private def self.loopback_host?(host : String) : Bool
        normalized = host.downcase
        normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1"
      end

      private def self.git_pointer_target(git_pointer_file : String, root : String) : String?
        if line = File.read_lines(git_pointer_file).first?
          marker = "gitdir:"
          if line.downcase.starts_with?(marker)
            target_raw = line[marker.size..].to_s.strip
            if !target_raw.empty?
              target = if Path[target_raw].absolute?
                         target_raw
                       else
                         File.join(root, target_raw)
                       end
              return normalize_path_for_sandbox(target)
            end
          end
        end
      rescue
        nil
      end
    end
  end
end
