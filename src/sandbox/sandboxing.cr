require "set"
require "./sandboxing/linux_sandbox"
require "./sandboxing/macos_permissions"
require "./sandboxing/seatbelt_permissions"
require "./sandboxing/macos_seatbelt"
require "./sandboxing/windows_sandbox"

module Sandbox
  module Sandboxing
    CODEX_SANDBOX_ENV_VAR                  = "CODEX_SANDBOX"
    CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR = "CODEX_SANDBOX_NETWORK_DISABLED"

    enum SandboxType
      None
      MacosSeatbelt
      LinuxSeccomp
      WindowsRestrictedToken
    end

    enum SandboxPreference
      Auto
      Require
      Forbid
    end

    enum WindowsSandboxLevel
      Disabled
      RestrictedToken
    end

    enum FileSystemSandboxKind
      Restricted
      Unrestricted
      ExternalSandbox
    end

    enum NetworkSandboxPolicy
      Enabled
      Restricted
    end

    struct NetworkPermissions
      getter? enabled : Bool

      def initialize(@enabled : Bool = false)
      end
    end

    struct FileSystemPermissions
      getter read : Array(String)?
      getter write : Array(String)?

      def initialize(
        @read : Array(String)? = nil,
        @write : Array(String)? = nil,
      )
      end

      def empty? : Bool
        (read || [] of String).empty? &&
          (write || [] of String).empty?
      end
    end

    struct PermissionProfile
      getter network : NetworkPermissions?
      getter file_system : FileSystemPermissions?
      getter macos : MacosSeatbeltProfileExtensions?

      def initialize(
        @network : NetworkPermissions? = nil,
        @file_system : FileSystemPermissions? = nil,
        @macos : MacosSeatbeltProfileExtensions? = nil,
      )
      end
    end

    struct FileSystemSandboxPolicy
      getter kind : FileSystemSandboxKind
      getter? full_disk_write_access : Bool

      def initialize(
        @kind : FileSystemSandboxKind,
        @full_disk_write_access : Bool = false,
      )
      end

      def self.unrestricted : self
        new(FileSystemSandboxKind::Unrestricted)
      end

      def self.external : self
        new(FileSystemSandboxKind::ExternalSandbox)
      end

      def self.restricted(full_disk_write_access : Bool = false) : self
        new(FileSystemSandboxKind::Restricted, full_disk_write_access)
      end
    end

    struct CommandSpec
      getter program : String
      getter args : Array(String)
      getter cwd : String
      getter env : Hash(String, String)
      getter sandbox_permissions : String
      getter justification : String?

      def initialize(
        @program : String,
        @args : Array(String) = [] of String,
        @cwd : String = Dir.current,
        @env : Hash(String, String) = Hash(String, String).new,
        @sandbox_permissions : String = "use_default",
        @justification : String? = nil,
      )
      end
    end

    struct ExecRequest
      getter command : Array(String)
      getter cwd : String
      getter env : Hash(String, String)
      getter sandbox : SandboxType
      getter windows_sandbox_level : WindowsSandboxLevel
      getter sandbox_permissions : String
      getter file_system_sandbox_policy : FileSystemSandboxPolicy
      getter network_sandbox_policy : NetworkSandboxPolicy
      getter justification : String?
      getter arg0 : String?

      def initialize(
        @command : Array(String),
        @cwd : String,
        @env : Hash(String, String),
        @sandbox : SandboxType,
        @windows_sandbox_level : WindowsSandboxLevel,
        @sandbox_permissions : String,
        @file_system_sandbox_policy : FileSystemSandboxPolicy,
        @network_sandbox_policy : NetworkSandboxPolicy,
        @justification : String? = nil,
        @arg0 : String? = nil,
      )
      end
    end

    class SandboxTransformError < Exception
    end

    class MissingLinuxSandboxExecutableError < SandboxTransformError
      def initialize
        super("missing codex-linux-sandbox executable path")
      end
    end

    class SeatbeltUnavailableError < SandboxTransformError
      def initialize
        super("seatbelt sandbox is only available on macOS")
      end
    end

    class SandboxManager
      def self.new : self
        super
      end

      def select_initial(
        file_system_policy : FileSystemSandboxPolicy,
        network_policy : NetworkSandboxPolicy,
        pref : SandboxPreference,
        windows_sandbox_level : WindowsSandboxLevel,
        has_managed_network_requirements : Bool,
      ) : SandboxType
        case pref
        in .forbid?
          SandboxType::None
        in .require?
          platform_sandbox(windows_sandbox_level)
        in .auto?
          if Sandboxing.should_require_platform_sandbox(
               file_system_policy,
               network_policy,
               has_managed_network_requirements
             )
            platform_sandbox(windows_sandbox_level)
          else
            SandboxType::None
          end
        end
      end

      def transform(
        spec : CommandSpec,
        file_system_policy : FileSystemSandboxPolicy,
        network_policy : NetworkSandboxPolicy,
        sandbox : SandboxType,
        codex_linux_sandbox_exe : String? = nil,
        use_linux_sandbox_bwrap : Bool = false,
        windows_sandbox_level : WindowsSandboxLevel = WindowsSandboxLevel::Disabled,
      ) : ExecRequest
        env = spec.env.dup
        if network_policy.restricted?
          env[CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR] = "1"
        end

        command = [spec.program] + spec.args
        arg0 = nil

        case sandbox
        in .none?
          # no-op
        in .macos_seatbelt?
          {% if flag?(:darwin) %}
            command = MacosSeatbelt.create_command_args(command, file_system_policy, network_policy)
            command.unshift(MacosSeatbelt::EXECUTABLE)
            env[CODEX_SANDBOX_ENV_VAR] = "seatbelt"
          {% else %}
            raise SeatbeltUnavailableError.new
          {% end %}
        in .linux_seccomp?
          exe = codex_linux_sandbox_exe || raise MissingLinuxSandboxExecutableError.new
          command = LinuxSandbox.create_command_args(command, use_linux_sandbox_bwrap)
          command.unshift(exe)
          arg0 = "codex-linux-sandbox"
        in .windows_restricted_token?
          WindowsSandbox.validate_supported_level(windows_sandbox_level)
        end

        ExecRequest.new(
          command: command,
          cwd: spec.cwd,
          env: env,
          sandbox: sandbox,
          windows_sandbox_level: windows_sandbox_level,
          sandbox_permissions: spec.sandbox_permissions,
          file_system_sandbox_policy: file_system_policy,
          network_sandbox_policy: network_policy,
          justification: spec.justification,
          arg0: arg0
        )
      end

      private def platform_sandbox(windows_sandbox_level : WindowsSandboxLevel) : SandboxType
        Sandboxing.default_platform_sandbox(windows_sandbox_level)
      end

      def denied(sandbox : SandboxType, stderr : String, exit_code : Int32 = 1) : Bool
        return false if sandbox.none?
        return false if exit_code == 0

        message = stderr.downcase
        message.includes?("operation not permitted") ||
          message.includes?("permission denied") ||
          message.includes?("sandbox") ||
          message.includes?("access is denied")
      end
    end

    def self.new : SandboxManager
      SandboxManager.new
    end

    def self.default_platform_sandbox(windows_sandbox_level : WindowsSandboxLevel) : SandboxType
      {% if flag?(:darwin) %}
        SandboxType::MacosSeatbelt
      {% elsif flag?(:linux) %}
        SandboxType::LinuxSeccomp
      {% elsif flag?(:win32) %}
        windows_sandbox_level.disabled? ? SandboxType::None : SandboxType::WindowsRestrictedToken
      {% else %}
        SandboxType::None
      {% end %}
    end

    def self.should_require_platform_sandbox(
      file_system_policy : FileSystemSandboxPolicy,
      network_policy : NetworkSandboxPolicy,
      has_managed_network_requirements : Bool,
    ) : Bool
      return true if has_managed_network_requirements

      if network_policy.restricted?
        return !file_system_policy.kind.external_sandbox?
      end

      case file_system_policy.kind
      in .restricted?
        !file_system_policy.full_disk_write_access?
      in .unrestricted?, .external_sandbox?
        false
      end
    end

    def self.intersect_permission_profiles(
      requested : PermissionProfile,
      granted : PermissionProfile,
    ) : PermissionProfile
      network = if requested.network.try(&.enabled?) && granted.network.try(&.enabled?)
                  NetworkPermissions.new(enabled: true)
                end

      file_system = requested.file_system.try do |requested_fs|
        granted_fs = granted.file_system || FileSystemPermissions.new
        read = intersect_paths(requested_fs.read, granted_fs.read)
        write = intersect_paths(requested_fs.write, granted_fs.write)
        fs = FileSystemPermissions.new(read: read, write: write)
        fs.empty? ? nil : fs
      end

      macos = MacosPermissions.intersect_macos_seatbelt_profile_extensions(
        requested.macos,
        granted.macos
      )

      PermissionProfile.new(network: network, file_system: file_system, macos: macos)
    end

    def self.normalize_permission_profile(profile : PermissionProfile?) : PermissionProfile?
      if profile
        network = profile.network.try do |net|
          net.enabled? ? net : nil
        end

        file_system = profile.file_system.try do |paths|
          normalized = FileSystemPermissions.new(
            read: paths.read.try(&.reject(&.empty?)),
            write: paths.write.try(&.reject(&.empty?))
          )
          normalized.empty? ? nil : normalized
        end

        macos = profile.macos
        normalized = PermissionProfile.new(network: network, file_system: file_system, macos: macos)
        normalized.network || normalized.file_system || normalized.macos ? normalized : nil
      end
    end

    def self.merge_permission_profiles(
      base : PermissionProfile,
      additional : PermissionProfile?,
    ) : PermissionProfile
      return base unless additional

      network_enabled =
        base.network.try(&.enabled?) || additional.network.try(&.enabled?) || false
      network = network_enabled ? NetworkPermissions.new(enabled: true) : nil

      file_system = merge_file_system_permissions(base.file_system, additional.file_system)

      macos = MacosPermissions.merge_macos_seatbelt_profile_extensions(base.macos, additional.macos)
      PermissionProfile.new(network: network, file_system: file_system, macos: macos)
    end

    def self.merge_file_system_permissions(
      base : FileSystemPermissions?,
      additional : FileSystemPermissions?,
      denied_paths : Array(String) = [] of String,
    ) : FileSystemPermissions?
      merged_read = merge_paths(base.try(&.read), additional.try(&.read))
      merged_write = merge_paths(base.try(&.write), additional.try(&.write))

      unless denied_paths.empty?
        merged_read.reject! { |path| denied_path?(path, denied_paths) }
        merged_write.reject! { |path| denied_path?(path, denied_paths) }
      end

      if merged_read.empty? && merged_write.empty?
        nil
      else
        FileSystemPermissions.new(read: merged_read, write: merged_write)
      end
    end

    private def self.intersect_paths(
      requested : Array(String)?,
      granted : Array(String)?,
    ) : Array(String)?
      requested.try do |requested_paths|
        granted_set = (granted || [] of String).to_set
        intersected = requested_paths.select { |path| granted_set.includes?(path) }
        intersected.empty? ? nil : intersected
      end
    end

    private def self.merge_paths(lhs : Array(String)?, rhs : Array(String)?) : Array(String)
      merged = Set(String).new
      (lhs || [] of String).each { |path| merged.add(path) unless path.empty? }
      (rhs || [] of String).each { |path| merged.add(path) unless path.empty? }
      merged.to_a.sort
    end

    private def self.denied_path?(path : String, denied_paths : Array(String)) : Bool
      denied_paths.any? do |denied|
        path == denied || path.starts_with?("#{denied}/")
      end
    end
  end
end
