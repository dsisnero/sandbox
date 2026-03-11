require "./spec_helper"

describe Sandbox do
  it "loads the shard namespace" do
    Sandbox.should_not be_nil
  end
end

describe Sandbox::Sandboxing do
  manager = Sandbox::Sandboxing::SandboxManager.new

  it "defaults to no sandbox for unrestricted network+filesystem" do
    sandbox = manager.select_initial(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
      Sandbox::Sandboxing::SandboxPreference::Auto,
      Sandbox::Sandboxing::WindowsSandboxLevel::Disabled,
      false
    )

    sandbox.should eq(Sandbox::Sandboxing::SandboxType::None)
  end

  it "requires a platform sandbox when network is restricted" do
    sandbox = manager.select_initial(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
      Sandbox::Sandboxing::SandboxPreference::Auto,
      Sandbox::Sandboxing::WindowsSandboxLevel::Disabled,
      false
    )

    sandbox.should eq(
      Sandbox::Sandboxing.default_platform_sandbox(
        Sandbox::Sandboxing::WindowsSandboxLevel::Disabled
      )
    )
  end

  it "full access still uses platform sandbox for restricted network" do
    requires = Sandbox::Sandboxing.should_require_platform_sandbox(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
      false
    )
    requires.should be_true
  end

  it "external sandbox allows enabled network without requiring platform sandbox" do
    requires = Sandbox::Sandboxing.should_require_platform_sandbox(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.external,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
      false
    )
    requires.should be_false
  end

  it "adds network disabled env when policy is restricted" do
    request = manager.transform(
      Sandbox::Sandboxing::CommandSpec.new(
        program: "echo",
        args: ["hello"]
      ),
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
      Sandbox::Sandboxing::SandboxType::None
    )

    request.env[Sandbox::Sandboxing::CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR]?.should eq("1")
    request.command.should eq(["echo", "hello"])
  end

  it "transform with external sandbox and enabled network keeps network enabled env" do
    request = manager.transform(
      Sandbox::Sandboxing::CommandSpec.new(
        program: "echo",
        args: ["hello"]
      ),
      Sandbox::Sandboxing::FileSystemSandboxPolicy.external,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
      Sandbox::Sandboxing::SandboxType::None
    )

    request.env.has_key?(Sandbox::Sandboxing::CODEX_SANDBOX_NETWORK_DISABLED_ENV_VAR).should be_false
  end

  it "wraps linux sandbox command and arg0 when executable is provided" do
    request = manager.transform(
      Sandbox::Sandboxing::CommandSpec.new(
        program: "true"
      ),
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
      Sandbox::Sandboxing::SandboxType::LinuxSeccomp,
      codex_linux_sandbox_exe: "/tmp/codex-linux-sandbox",
      use_linux_sandbox_bwrap: true
    )

    request.command.should eq(
      ["/tmp/codex-linux-sandbox", "--use-bwrap", "--", "true"]
    )
    request.arg0.should eq("codex-linux-sandbox")
  end

  it "raises when linux sandbox executable is missing" do
    expect_raises(Sandbox::Sandboxing::MissingLinuxSandboxExecutableError) do
      manager.transform(
        Sandbox::Sandboxing::CommandSpec.new(program: "true"),
        Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        Sandbox::Sandboxing::SandboxType::LinuxSeccomp
      )
    end
  end

  {% if flag?(:darwin) %}
    it "wraps seatbelt command on macOS with /usr/bin/sandbox-exec" do
      request = manager.transform(
        Sandbox::Sandboxing::CommandSpec.new(program: "true"),
        Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        Sandbox::Sandboxing::SandboxType::MacosSeatbelt
      )

      request.command.first.should eq("/usr/bin/sandbox-exec")
      request.env[Sandbox::Sandboxing::CODEX_SANDBOX_ENV_VAR]?.should eq("seatbelt")
    end
  {% else %}
    it "raises seatbelt unavailable on non-macos hosts" do
      expect_raises(Sandbox::Sandboxing::SeatbeltUnavailableError) do
        manager.transform(
          Sandbox::Sandboxing::CommandSpec.new(program: "true"),
          Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
          Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
          Sandbox::Sandboxing::SandboxType::MacosSeatbelt
        )
      end
    end
  {% end %}

  it "detects likely sandbox denial from stderr text" do
    manager.denied(
      Sandbox::Sandboxing::SandboxType::LinuxSeccomp,
      "Operation not permitted",
      1
    ).should be_true
  end

  it "does not mark successful exit as denied" do
    manager.denied(
      Sandbox::Sandboxing::SandboxType::LinuxSeccomp,
      "permission denied",
      0
    ).should be_false
  end

  it "intersects permission profiles by common grants only" do
    requested = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: true),
      file_system: Sandbox::Sandboxing::FileSystemPermissions.new(
        read: ["/tmp/a", "/tmp/b"],
        write: ["/tmp/c", "/tmp/d"]
      )
    )
    granted = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: true),
      file_system: Sandbox::Sandboxing::FileSystemPermissions.new(
        read: ["/tmp/b"],
        write: ["/tmp/x", "/tmp/d"]
      )
    )

    intersection = Sandbox::Sandboxing.intersect_permission_profiles(requested, granted)
    intersection.network.try(&.enabled?).should be_true
    fs = intersection.file_system
    fs.should_not be_nil
    fs.try(&.read).should eq(["/tmp/b"])
    fs.try(&.write).should eq(["/tmp/d"])
  end

  it "drops network permission when grant does not include it" do
    requested = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: true)
    )
    granted = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: false)
    )

    intersection = Sandbox::Sandboxing.intersect_permission_profiles(requested, granted)
    intersection.network.should be_nil
  end

  it "intersects macos profile extensions in permission profiles" do
    requested = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
        macos_preferences: Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite,
        macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Notes"]),
        macos_accessibility: true
      )
    )
    granted = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default
    )

    intersection = Sandbox::Sandboxing.intersect_permission_profiles(requested, granted)
    intersection.macos.should eq(Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default)
  end

  it "intersect permission profiles preserves default macos grants" do
    requested = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default
    )
    granted = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default
    )

    intersection = Sandbox::Sandboxing.intersect_permission_profiles(requested, granted)
    intersection.macos.should eq(Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default)
  end

  it "normalizes permission profile by dropping empty nested profiles" do
    profile = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: false),
      file_system: Sandbox::Sandboxing::FileSystemPermissions.new(read: [""])
    )

    Sandbox::Sandboxing.normalize_permission_profile(profile).should be_nil
  end

  it "normalize permission profile preserves network and macos preferences defaults" do
    profile = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: true),
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default
    )

    normalized = Sandbox::Sandboxing.normalize_permission_profile(profile)
    normalized.should_not be_nil
    normalized.try(&.network).try(&.enabled?).should be_true
    normalized.try(&.macos).should eq(Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default)
  end

  it "normalizes permission profile preserves macos permissions" do
    profile = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
        macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadOnly
      )
    )

    normalized = Sandbox::Sandboxing.normalize_permission_profile(profile)
    normalized.should_not be_nil
    normalized.try(&.macos).try(&.macos_contacts).should eq(
      Sandbox::Sandboxing::MacosContactsPermission::ReadOnly
    )
  end

  it "merges macos extensions with additional permissions" do
    base = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default
    )
    additional = Sandbox::Sandboxing::PermissionProfile.new(
      macos: Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
        macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadWrite
      )
    )

    merged = Sandbox::Sandboxing.merge_permission_profiles(base, additional)
    merged.macos.should_not be_nil
    merged.macos.try(&.macos_preferences).should eq(
      Sandbox::Sandboxing::MacosPreferencesPermission::ReadOnly
    )
    merged.macos.try(&.macos_contacts).should eq(
      Sandbox::Sandboxing::MacosContactsPermission::ReadWrite
    )
  end

  it "read-only additional permissions can enable network without writes" do
    base = Sandbox::Sandboxing::PermissionProfile.new(
      file_system: Sandbox::Sandboxing::FileSystemPermissions.new(read: ["/tmp"])
    )
    additional = Sandbox::Sandboxing::PermissionProfile.new(
      network: Sandbox::Sandboxing::NetworkPermissions.new(enabled: true)
    )

    merged = Sandbox::Sandboxing.merge_permission_profiles(base, additional)
    merged.network.try(&.enabled?).should be_true
    merged.file_system.should_not be_nil
    merged.file_system.try(&.write).should eq([] of String)
  end

  it "merge file system policy with additional permissions preserves unreadable roots" do
    base = Sandbox::Sandboxing::FileSystemPermissions.new(
      read: ["/tmp", "/tmp/private"],
      write: ["/tmp/private/file.txt"]
    )
    additional = Sandbox::Sandboxing::FileSystemPermissions.new(
      read: ["/tmp/private/child"],
      write: ["/tmp/public"]
    )

    merged = Sandbox::Sandboxing.merge_file_system_permissions(
      base,
      additional,
      denied_paths: ["/tmp/private"]
    )
    merged.should_not be_nil
    merged.try(&.read).should eq(["/tmp"])
    merged.try(&.write).should eq(["/tmp/public"])
  end

  it "transform additional permissions preserves denied entries" do
    base = Sandbox::Sandboxing::FileSystemPermissions.new(
      read: ["/tmp/a"],
      write: ["/tmp/a/secret", "/tmp/a/public"]
    )
    additional = Sandbox::Sandboxing::FileSystemPermissions.new(
      write: ["/tmp/a/secret/child"]
    )

    merged = Sandbox::Sandboxing.merge_file_system_permissions(
      base,
      additional,
      denied_paths: ["/tmp/a/secret"]
    )
    merged.should_not be_nil
    merged.try(&.write).should eq(["/tmp/a/public"])
  end

  it "includes default seatbelt extension clauses in generated profile" do
    profile = Sandbox::Sandboxing::MacosSeatbelt.profile_for(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted
    )
    profile.includes?("user-preference-read").should be_true
  end

  it "keeps legacy preferences read access when extension profile is omitted" do
    profile = Sandbox::Sandboxing::MacosSeatbelt.profile_for(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
      nil
    )
    profile.includes?("user-preference-read").should be_true
    profile.includes?("user-preference-write").should be_false
  end

  it "includes macos permission extensions when provided" do
    profile = Sandbox::Sandboxing::MacosSeatbelt.profile_for(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
      Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
        macos_preferences: Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite,
        macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(
          ["com.apple.Notes"]
        )
      )
    )
    profile.includes?("user-preference-write").should be_true
    profile.includes?("appleevent-destination \"com.apple.Notes\"").should be_true
  end

  it "keeps lsopen denied when automation is bundle-scoped" do
    profile = Sandbox::Sandboxing::MacosSeatbelt.profile_for(
      Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted,
      Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
      Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
        macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(
          ["com.apple.Notes"]
        )
      )
    )

    profile.includes?("appleevent-destination \"com.apple.Notes\"").should be_true
    profile.includes?("lsopen").should be_false
  end
end

{% if flag?(:linux) %}
  describe Sandbox::Sandboxing::LinuxSandbox do
    it "classifies proxy mode as highest priority network mode" do
      mode = Sandbox::Sandboxing::LinuxSandbox.bwrap_network_mode(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        true
      )
      mode.should eq(Sandbox::Sandboxing::LinuxSandbox::BwrapNetworkMode::ProxyOnly)
    end

    it "enforces seccomp for managed network even with full network policy" do
      Sandbox::Sandboxing::LinuxSandbox.should_install_network_seccomp(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        true
      ).should be_true
    end

    it "skips seccomp for full network policy without managed network" do
      Sandbox::Sandboxing::LinuxSandbox.should_install_network_seccomp(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        false
      ).should be_false
    end

    it "always installs seccomp for restricted network policy" do
      Sandbox::Sandboxing::LinuxSandbox.should_install_network_seccomp(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        false
      ).should be_true
      Sandbox::Sandboxing::LinuxSandbox.should_install_network_seccomp(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        true
      ).should be_true
    end

    it "uses proxy-routed seccomp mode for managed proxy routes" do
      Sandbox::Sandboxing::LinuxSandbox.network_seccomp_mode(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        true,
        true
      ).should eq(Sandbox::Sandboxing::LinuxSandbox::SeccompNetworkMode::ProxyRouted)
    end

    it "uses restricted seccomp mode for restricted network without proxy routing" do
      Sandbox::Sandboxing::LinuxSandbox.network_seccomp_mode(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        false,
        false
      ).should eq(Sandbox::Sandboxing::LinuxSandbox::SeccompNetworkMode::Restricted)
    end

    it "returns no seccomp mode for full network without managed proxy" do
      Sandbox::Sandboxing::LinuxSandbox.network_seccomp_mode(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        false,
        false
      ).should be_nil
    end

    it "mounts /dev before writable /dev binds" do
      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_filesystem_args(
        readable_roots: ["/"],
        writable_roots: ["/", "/dev"],
        unreadable_roots: [] of String,
        full_disk_read_access: true
      )

      args.should eq(
        [
          "--ro-bind",
          "/",
          "/",
          "--dev",
          "/dev",
          "--bind",
          "/",
          "/",
          "--bind",
          "/dev",
          "/dev",
        ]
      )
    end

    it "uses scoped readable roots for restricted read-only mode" do
      temp = "/tmp/linux-bwrap-readable-#{Random.rand(100_000)}"
      readable_root = File.join(temp, "readable")
      Dir.mkdir_p(readable_root)

      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_filesystem_args(
        readable_roots: [readable_root],
        writable_roots: [] of String,
        unreadable_roots: [] of String,
        full_disk_read_access: false
      )

      args[0, 4].should eq(["--tmpfs", "/", "--dev", "/dev"])
      args.each_cons(3).any? { |slice| slice == ["--ro-bind", readable_root, readable_root] }.should be_true
      FileUtils.rm_rf(temp)
    end

    it "includes /usr as platform default read root when requested and present" do
      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_filesystem_args(
        readable_roots: [] of String,
        writable_roots: [] of String,
        unreadable_roots: [] of String,
        full_disk_read_access: false,
        include_platform_defaults: true
      )

      if Dir.exists?("/usr")
        args.each_cons(3).any? { |slice| slice == ["--ro-bind", "/usr", "/usr"] }.should be_true
      end
    end

    it "masks root-read directory carveouts with tmpfs" do
      temp = "/tmp/linux-bwrap-mask-dir-#{Random.rand(100_000)}"
      unreadable = File.join(temp, "private")
      Dir.mkdir_p(unreadable)

      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_filesystem_args(
        readable_roots: ["/"],
        writable_roots: [] of String,
        unreadable_roots: [unreadable],
        full_disk_read_access: true
      )

      args.each_cons(2).any? { |slice| slice == ["--tmpfs", unreadable] }.should be_true
      FileUtils.rm_rf(temp)
    end

    it "masks root-read file carveouts with tmpfs" do
      temp = "/tmp/linux-bwrap-mask-file-#{Random.rand(100_000)}"
      unreadable = File.join(temp, "secret.txt")
      Dir.mkdir_p(temp)
      File.write(unreadable, "secret")

      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_filesystem_args(
        readable_roots: ["/"],
        writable_roots: [] of String,
        unreadable_roots: [unreadable],
        full_disk_read_access: true
      )

      args.each_cons(2).any? { |slice| slice == ["--tmpfs", unreadable] }.should be_true
      FileUtils.rm_rf(temp)
    end

    it "reapplies unreadable carveouts after writable binds" do
      temp = "/tmp/linux-bwrap-carveout-order-#{Random.rand(100_000)}"
      writable = File.join(temp, "workspace")
      unreadable = File.join(writable, ".git")
      Dir.mkdir_p(unreadable)

      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_filesystem_args(
        readable_roots: ["/"],
        writable_roots: [writable],
        unreadable_roots: [unreadable],
        full_disk_read_access: true
      )

      bind_idx = args.index("--bind")
      mask_idx = args.index("--tmpfs")
      bind_idx.should_not be_nil
      mask_idx.should_not be_nil
      if bind = bind_idx
        if mask = mask_idx
          mask.should be > bind
        end
      end
      FileUtils.rm_rf(temp)
    end

    it "returns unwrapped command for full disk write + full network bwrap mode" do
      command = ["/bin/true"]
      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_command_args(
        command,
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted(full_disk_write_access: true),
        Sandbox::Sandboxing::LinuxSandbox::BwrapNetworkMode::FullAccess
      )

      args.should eq(command)
    end

    it "wraps full filesystem command and unshares network for proxy-only mode" do
      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_command_args(
        ["/bin/true"],
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted(full_disk_write_access: true),
        Sandbox::Sandboxing::LinuxSandbox::BwrapNetworkMode::ProxyOnly
      )

      args.should eq(
        [
          "--new-session",
          "--die-with-parent",
          "--bind",
          "/",
          "/",
          "--unshare-user",
          "--unshare-pid",
          "--unshare-net",
          "--proc",
          "/proc",
          "--",
          "/bin/true",
        ]
      )
    end

    it "unshares network when isolated network mode is requested" do
      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_command_args(
        ["/bin/true"],
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted,
        Sandbox::Sandboxing::LinuxSandbox::BwrapNetworkMode::Isolated
      )

      args.includes?("--unshare-net").should be_true
    end

    it "unshares network when proxy-only network mode is requested" do
      args = Sandbox::Sandboxing::LinuxSandbox.create_bwrap_command_args(
        ["/bin/true"],
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted,
        Sandbox::Sandboxing::LinuxSandbox::BwrapNetworkMode::ProxyOnly
      )

      args.includes?("--unshare-net").should be_true
    end

    it "detects known proc mount failures" do
      stderr = "bwrap: Can't mount proc on /newroot/proc: Permission denied"
      Sandbox::Sandboxing::LinuxSandbox.proc_mount_failure?(stderr).should be_true
    end

    it "detects proc mount invalid argument failure" do
      stderr = "bwrap: Can't mount proc on /newroot/proc: Invalid argument"
      Sandbox::Sandboxing::LinuxSandbox.proc_mount_failure?(stderr).should be_true
    end

    it "detects proc mount operation not permitted failure" do
      stderr = "bwrap: Can't mount proc on /newroot/proc: Operation not permitted"
      Sandbox::Sandboxing::LinuxSandbox.proc_mount_failure?(stderr).should be_true
    end

    it "ignores non proc mount errors" do
      stderr = "bwrap: Failed to open /newroot/etc/hosts: Permission denied"
      Sandbox::Sandboxing::LinuxSandbox.proc_mount_failure?(stderr).should be_false
    end

    it "rejects inner seccomp mode without bwrap" do
      expect_raises(Exception, /requires --use-bwrap-sandbox/) do
        Sandbox::Sandboxing::LinuxSandbox.ensure_inner_stage_mode_is_valid(true, false)
      end
    end

    it "builds inner seccomp command with split-policy flags" do
      cmd = Sandbox::Sandboxing::LinuxSandbox::LandlockCommand.new(
        sandbox_policy_cwd: "/tmp",
        use_bwrap_sandbox: true,
        command: ["/bin/true"]
      )

      inner = Sandbox::Sandboxing::LinuxSandbox.build_inner_seccomp_command(
        cmd,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        "/tmp/codex-linux-sandbox"
      )

      inner.includes?("--file-system-sandbox-policy").should be_true
      inner.includes?("--network-sandbox-policy").should be_true
      inner.includes?("--apply-seccomp-then-exec").should be_true
    end

    it "keeps sandbox argv0 before command separator" do
      cmd = Sandbox::Sandboxing::LinuxSandbox::LandlockCommand.new(
        sandbox_policy_cwd: "/tmp",
        use_bwrap_sandbox: true,
        command: ["/bin/true"]
      )

      inner = Sandbox::Sandboxing::LinuxSandbox.build_inner_seccomp_command(
        cmd,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        "codex-linux-sandbox"
      )

      inner.first.should eq("codex-linux-sandbox")
      separator_index = inner.index("--")
      separator_index.should_not be_nil
      if index = separator_index
        index.should be > 0
      end
      inner.last.should eq("/bin/true")
    end

    it "requires proxy route spec for managed proxy inner command" do
      cmd = Sandbox::Sandboxing::LinuxSandbox::LandlockCommand.new(
        sandbox_policy_cwd: "/tmp",
        use_bwrap_sandbox: true,
        allow_network_for_proxy: true,
        command: ["/bin/true"]
      )

      expect_raises(Exception, /requires --proxy-route-spec/) do
        Sandbox::Sandboxing::LinuxSandbox.build_inner_seccomp_command(
          cmd,
          Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
          "/tmp/codex-linux-sandbox"
        )
      end
    end

    it "includes route spec in managed proxy inner command when present" do
      cmd = Sandbox::Sandboxing::LinuxSandbox::LandlockCommand.new(
        sandbox_policy_cwd: "/tmp",
        use_bwrap_sandbox: true,
        allow_network_for_proxy: true,
        proxy_route_spec: %({"routes":[{"env_key":"HTTP_PROXY","uds_path":"/tmp/proxy.sock"}]}),
        command: ["/bin/true"]
      )

      inner = Sandbox::Sandboxing::LinuxSandbox.build_inner_seccomp_command(
        cmd,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        "/tmp/codex-linux-sandbox"
      )

      inner.includes?("--allow-network-for-proxy").should be_true
      inner.includes?("--proxy-route-spec").should be_true
      inner.includes?(%({"routes":[{"env_key":"HTTP_PROXY","uds_path":"/tmp/proxy.sock"}]})).should be_true
    end

    it "managed proxy preflight for full access still wraps command with separator" do
      cmd = Sandbox::Sandboxing::LinuxSandbox::LandlockCommand.new(
        sandbox_policy_cwd: "/tmp",
        use_bwrap_sandbox: true,
        allow_network_for_proxy: true,
        proxy_route_spec: %({"routes":[{"env_key":"HTTP_PROXY","uds_path":"/tmp/proxy.sock"}]}),
        command: ["/bin/true"]
      )
      inner = Sandbox::Sandboxing::LinuxSandbox.run_main(
        cmd,
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted(full_disk_write_access: true),
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        "codex-linux-sandbox"
      )

      inner.first.should eq("codex-linux-sandbox")
      inner.includes?("--").should be_true
    end

    it "omits proxy route spec when managed proxy is disabled" do
      cmd = Sandbox::Sandboxing::LinuxSandbox::LandlockCommand.new(
        sandbox_policy_cwd: "/tmp",
        use_bwrap_sandbox: true,
        allow_network_for_proxy: false,
        command: ["/bin/true"]
      )
      inner = Sandbox::Sandboxing::LinuxSandbox.build_inner_seccomp_command(
        cmd,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        "/tmp/codex-linux-sandbox"
      )
      inner.includes?("--proxy-route-spec").should be_false
    end

    it "accepts valid inner stage modes" do
      Sandbox::Sandboxing::LinuxSandbox.ensure_inner_stage_mode_is_valid(false, false)
      Sandbox::Sandboxing::LinuxSandbox.ensure_inner_stage_mode_is_valid(false, true)
      Sandbox::Sandboxing::LinuxSandbox.ensure_inner_stage_mode_is_valid(true, true)
    end

    it "derives split policies from legacy policy" do
      resolved = Sandbox::Sandboxing::LinuxSandbox.resolve_sandbox_policies(
        "/tmp",
        Sandbox::Sandboxing::LinuxSandbox::LegacySandboxPolicy::ReadOnly,
        nil,
        nil
      )

      resolved.sandbox_policy.should eq(
        Sandbox::Sandboxing::LinuxSandbox::LegacySandboxPolicy::ReadOnly
      )
      resolved.file_system_sandbox_policy.kind.should eq(
        Sandbox::Sandboxing::FileSystemSandboxKind::Restricted
      )
      resolved.network_sandbox_policy.should eq(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted
      )
    end

    it "derives legacy policy from split policies" do
      resolved = Sandbox::Sandboxing::LinuxSandbox.resolve_sandbox_policies(
        "/tmp",
        nil,
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted(full_disk_write_access: true),
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted
      )

      resolved.sandbox_policy.should eq(
        Sandbox::Sandboxing::LinuxSandbox::LegacySandboxPolicy::WorkspaceWrite
      )
    end

    it "rejects partial split policies" do
      expect_raises(Exception, /must be provided together/) do
        Sandbox::Sandboxing::LinuxSandbox.resolve_sandbox_policies(
          "/tmp",
          Sandbox::Sandboxing::LinuxSandbox::LegacySandboxPolicy::ReadOnly,
          Sandbox::Sandboxing::FileSystemSandboxPolicy.unrestricted,
          nil
        )
      end
    end

    it "recognizes proxy env keys case-insensitively" do
      Sandbox::Sandboxing::LinuxSandbox.proxy_env_key?("HTTP_PROXY").should be_true
      Sandbox::Sandboxing::LinuxSandbox.proxy_env_key?("http_proxy").should be_true
      Sandbox::Sandboxing::LinuxSandbox.proxy_env_key?("PATH").should be_false
    end

    it "parses loopback proxy endpoint and ignores non-loopback endpoint" do
      Sandbox::Sandboxing::LinuxSandbox.parse_loopback_proxy_endpoint(
        "http://127.0.0.1:43128"
      ).should eq("127.0.0.1:43128")
      Sandbox::Sandboxing::LinuxSandbox.parse_loopback_proxy_endpoint(
        "http://example.com:3128"
      ).should be_nil
    end

    it "plans proxy routes from valid loopback env entries only" do
      env = {
        "HTTP_PROXY"  => "http://127.0.0.1:43128",
        "HTTPS_PROXY" => "http://example.com:3128",
        "PATH"        => "/usr/bin",
      }
      plan = Sandbox::Sandboxing::LinuxSandbox.plan_proxy_routes(env)

      plan.has_proxy_config?.should be_true
      plan.routes.size.should eq(1)
      plan.routes.first.env_key.should eq("HTTP_PROXY")
      plan.routes.first.endpoint.should eq("127.0.0.1:43128")
    end

    it "rewrites proxy url to local loopback port" do
      rewritten = Sandbox::Sandboxing::LinuxSandbox.rewrite_proxy_env_value(
        "socks5h://127.0.0.1:8081",
        43210
      )
      rewritten.should eq("socks5h://127.0.0.1:43210")
    end

    it "returns expected default proxy ports" do
      Sandbox::Sandboxing::LinuxSandbox.default_proxy_port("http").should eq(80)
      Sandbox::Sandboxing::LinuxSandbox.default_proxy_port("https").should eq(443)
      Sandbox::Sandboxing::LinuxSandbox.default_proxy_port("socks5h").should eq(1080)
    end

    it "parses proxy socket dir owner pid from directory names" do
      Sandbox::Sandboxing::LinuxSandbox.parse_proxy_socket_dir_owner_pid(
        "codex-linux-sandbox-proxy-1234-0"
      ).should eq(1234)
      Sandbox::Sandboxing::LinuxSandbox.parse_proxy_socket_dir_owner_pid(
        "codex-linux-sandbox-proxy-x"
      ).should be_nil
      Sandbox::Sandboxing::LinuxSandbox.parse_proxy_socket_dir_owner_pid(
        "not-a-proxy-dir"
      ).should be_nil
    end

    it "cleans stale proxy socket dirs while leaving unrelated dirs" do
      temp = "/tmp/proxy-routing-spec-#{Random.rand(100_000)}"
      Dir.mkdir_p(temp)
      stale = File.join(temp, "codex-linux-sandbox-proxy-99999-0")
      unrelated = File.join(temp, "unrelated-proxy-dir")
      Dir.mkdir(stale)
      Dir.mkdir(unrelated)

      Sandbox::Sandboxing::LinuxSandbox.cleanup_stale_proxy_socket_dirs_in(temp)

      Dir.exists?(stale).should be_false
      Dir.exists?(unrelated).should be_true
      FileUtils.rm_rf(temp)
    end

    it "cleanup_proxy_socket_dir removes bridge artifacts" do
      temp = "/tmp/proxy-routing-cleanup-#{Random.rand(100_000)}"
      socket_dir = File.join(temp, "codex-linux-sandbox-proxy-test")
      Dir.mkdir_p(socket_dir)
      marker = File.join(socket_dir, "bridge.sock")
      File.write(marker, "test")

      Sandbox::Sandboxing::LinuxSandbox.cleanup_proxy_socket_dir(socket_dir)

      Dir.exists?(socket_dir).should be_false
      FileUtils.rm_rf(temp)
    end

    it "proxy route spec serialization omits proxy urls" do
      spec = Sandbox::Sandboxing::LinuxSandbox::ProxyRouteSpec.new(
        [
          Sandbox::Sandboxing::LinuxSandbox::ProxyRouteEntry.new(
            "HTTP_PROXY",
            "/tmp/proxy-route-0.sock"
          ),
        ]
      )

      serialized = Sandbox::Sandboxing::LinuxSandbox.serialize_proxy_route_spec(spec)
      serialized.should eq(
        %({"routes":[{"env_key":"HTTP_PROXY","uds_path":"/tmp/proxy-route-0.sock"}]})
      )
    end
  end
{% end %}

describe Sandbox::Sandboxing::WindowsSandbox do
  it "parses read-only policy preset" do
    policy = Sandbox::Sandboxing::WindowsSandbox.parse_policy("read-only")
    policy.kind.should eq(Sandbox::Sandboxing::WindowsSandbox::PolicyKind::ReadOnly)
  end

  it "parses read-only policy json payload" do
    policy = Sandbox::Sandboxing::WindowsSandbox.parse_policy(%({"kind":"ReadOnly"}))
    policy.kind.should eq(Sandbox::Sandboxing::WindowsSandbox::PolicyKind::ReadOnly)
  end

  it "parses workspace-write policy json payload with roots and exclusions" do
    policy = Sandbox::Sandboxing::WindowsSandbox.parse_policy(
      %({"kind":"WorkspaceWrite","network_access":true,"writable_roots":["/tmp/one","/tmp/two"],"exclude_tmpdir_env_var":true,"exclude_slash_tmp":true})
    )
    policy.kind.should eq(Sandbox::Sandboxing::WindowsSandbox::PolicyKind::WorkspaceWrite)
    policy.network_access?.should be_true
    policy.writable_roots.should eq(["/tmp/one", "/tmp/two"])
    policy.exclude_tmpdir_env_var?.should be_true
    policy.exclude_slash_tmp?.should be_true
  end

  it "rejects external-sandbox policy preset" do
    expect_raises(Exception, /DangerFullAccess and ExternalSandbox/) do
      Sandbox::Sandboxing::WindowsSandbox.parse_policy("external-sandbox")
    end
  end

  it "rejects external-sandbox json payload" do
    expect_raises(Exception, /DangerFullAccess and ExternalSandbox/) do
      Sandbox::Sandboxing::WindowsSandbox.parse_policy(%({"kind":"ExternalSandbox"}))
    end
  end

  it "normalizes case and separators for canonical path keys" do
    windows_style = "C:\\Users\\Dev\\Repo"
    slash_style = "c:/users/dev/repo"

    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(windows_style).should eq(
      Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(slash_style)
    )
  end

  it "redacts username path segments" do
    usernames = ["Alice", "Bob"]
    msg = "failed to write C:\\Users\\Alice\\file.txt; fallback D:\\Profiles\\Bob\\x"
    redacted = Sandbox::Sandboxing::WindowsSandbox.redact_username_segments(msg, usernames)
    redacted.should eq(
      "failed to write C:\\Users\\<user>\\file.txt; fallback D:\\Profiles\\<user>\\x"
    )
  end

  it "keeps unknown path segments unchanged" do
    usernames = ["Alice"]
    msg = "failed to write E:\\data\\file.txt"
    redacted = Sandbox::Sandboxing::WindowsSandbox.redact_username_segments(msg, usernames)
    redacted.should eq(msg)
  end

  it "redacts multiple username segment occurrences" do
    usernames = ["Alice"]
    msg = "C:\\Users\\Alice\\a and C:\\Users\\Alice\\b"
    redacted = Sandbox::Sandboxing::WindowsSandbox.redact_username_segments(msg, usernames)
    redacted.should eq("C:\\Users\\<user>\\a and C:\\Users\\<user>\\b")
  end

  it "writes reads and clears setup error report" do
    temp = "/tmp/windows-setup-error-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    report = Sandbox::Sandboxing::WindowsSandbox::SetupErrorReport.new(
      Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperLogFailed,
      "failed to write C:\\Users\\Alice\\file.txt"
    )

    Sandbox::Sandboxing::WindowsSandbox.write_setup_error_report(codex_home, report)
    loaded = Sandbox::Sandboxing::WindowsSandbox.read_setup_error_report(codex_home)
    loaded.should_not be_nil
    loaded.try(&.code).should eq(Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperLogFailed)
    loaded.try(&.message).should eq("failed to write C:\\Users\\Alice\\file.txt")

    Sandbox::Sandboxing::WindowsSandbox.clear_setup_error_report(codex_home)
    Sandbox::Sandboxing::WindowsSandbox.read_setup_error_report(codex_home).should be_nil
    FileUtils.rm_rf(temp)
  end

  it "maps setup error reports to setup failures and sanitizes metric messages" do
    report = Sandbox::Sandboxing::WindowsSandbox::SetupErrorReport.new(
      Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperLogFailed,
      "failed to write C:\\Users\\Alice\\file.txt"
    )

    failure = Sandbox::Sandboxing::WindowsSandbox.from_report(report)
    failure.code.should eq(Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperLogFailed)
    metric = Sandbox::Sandboxing::WindowsSandbox.metric_message(failure)
    metric.empty?.should be_false
    metric.includes?("failed").should be_true
    metric.includes?("\\").should be_false
  end

  it "extracts setup failures from exceptions" do
    setup_failure = Sandbox::Sandboxing::WindowsSandbox.failure(
      Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperUnknownError,
      "boom"
    )
    extracted = Sandbox::Sandboxing::WindowsSandbox.extract_failure(setup_failure)
    extracted.should_not be_nil
    extracted.try(&.code).should eq(Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperUnknownError)

    Sandbox::Sandboxing::WindowsSandbox.extract_failure(Exception.new("other")).should be_nil
  end

  it "exposes setup error code string names for helper variants" do
    Sandbox::Sandboxing::WindowsSandbox.as_str(
      Sandbox::Sandboxing::WindowsSandbox::SetupErrorCode::HelperFirewallRuleVerifyFailed
    ).should eq("helper_firewall_rule_verify_failed")
  end

  it "command preview truncates safely at utf8 boundaries" do
    prefix = "x" * (Sandbox::Sandboxing::WindowsSandbox::LOG_COMMAND_PREVIEW_LIMIT - 1)
    command = ["#{prefix}😀"]
    preview = Sandbox::Sandboxing::WindowsSandbox.preview_command(command)
    preview.bytesize.should be <= Sandbox::Sandboxing::WindowsSandbox::LOG_COMMAND_PREVIEW_LIMIT
  end

  it "writes note lines to sandbox log" do
    temp = "/tmp/windows-log-note-#{Random.rand(100_000)}"
    Dir.mkdir_p(temp)

    Sandbox::Sandboxing::WindowsSandbox.log_note("hello-log", temp)
    log_path = File.join(temp, Sandbox::Sandboxing::WindowsSandbox::LOG_FILE_NAME)
    File.exists?(log_path).should be_true
    File.read(log_path).includes?("hello-log").should be_true
    FileUtils.rm_rf(temp)
  end

  it "writes start success and failure entries to sandbox log" do
    temp = "/tmp/windows-log-lifecycle-#{Random.rand(100_000)}"
    Dir.mkdir_p(temp)
    command = ["cmd", "/c", "echo", "hello"]

    Sandbox::Sandboxing::WindowsSandbox.log_start(command, temp)
    Sandbox::Sandboxing::WindowsSandbox.log_success(command, temp)
    Sandbox::Sandboxing::WindowsSandbox.log_failure(command, "boom", temp)

    log_path = File.join(temp, Sandbox::Sandboxing::WindowsSandbox::LOG_FILE_NAME)
    contents = File.read(log_path)
    contents.includes?("START: cmd /c echo hello").should be_true
    contents.includes?("SUCCESS: cmd /c echo hello").should be_true
    contents.includes?("FAILURE: cmd /c echo hello (boom)").should be_true
    FileUtils.rm_rf(temp)
  end

  it "debug log writes only when SBX_DEBUG is enabled" do
    temp = "/tmp/windows-log-debug-#{Random.rand(100_000)}"
    Dir.mkdir_p(temp)
    log_path = File.join(temp, Sandbox::Sandboxing::WindowsSandbox::LOG_FILE_NAME)

    Sandbox::Sandboxing::WindowsSandbox.debug_log(
      "disabled-message",
      temp,
      {"SBX_DEBUG" => "0"}
    )
    File.exists?(log_path).should be_false

    Sandbox::Sandboxing::WindowsSandbox.debug_log(
      "enabled-message",
      temp,
      {"SBX_DEBUG" => "1"}
    )
    File.exists?(log_path).should be_true
    File.read(log_path).includes?("DEBUG: enabled-message").should be_true
    FileUtils.rm_rf(temp)
  end

  it "normalizes /dev/null style values to NUL" do
    env = {
      "A" => "/dev/null",
      "B" => "\\\\dev\\\\null",
      "C" => "keep",
    }
    Sandbox::Sandboxing::WindowsSandbox.normalize_null_device_env(env)
    env["A"].should eq("NUL")
    env["B"].should eq("NUL")
    env["C"].should eq("keep")
  end

  it "sets non-interactive pager defaults" do
    env = {} of String => String
    Sandbox::Sandboxing::WindowsSandbox.ensure_non_interactive_pager(env)
    env["GIT_PAGER"].should eq("more.com")
    env["PAGER"].should eq("more.com")
    env["LESS"].should eq("")
  end

  it "inherits PATH and PATHEXT when missing" do
    env = {} of String => String
    inherited = {
      "PATH"    => "C:\\Windows\\System32",
      "PATHEXT" => ".COM;.EXE;.BAT;.CMD",
    }
    Sandbox::Sandboxing::WindowsSandbox.inherit_path_env(env, inherited)
    env["PATH"].should eq("C:\\Windows\\System32")
    env["PATHEXT"].should eq(".COM;.EXE;.BAT;.CMD")
  end

  it "applies no-network environment defaults" do
    env = {} of String => String
    Sandbox::Sandboxing::WindowsSandbox.apply_no_network_to_env(env)
    env["SBX_NONET_ACTIVE"].should eq("1")
    env["HTTP_PROXY"].should eq("http://127.0.0.1:9")
    env["HTTPS_PROXY"].should eq("http://127.0.0.1:9")
    env["ALL_PROXY"].should eq("http://127.0.0.1:9")
    env["GIT_SSH_COMMAND"].should eq("cmd /c exit 1")
  end

  it "includes additional writable roots in allow paths" do
    temp = "/tmp/windows-allow-paths-#{Random.rand(100_000)}"
    command_cwd = File.join(temp, "workspace")
    extra_root = File.join(temp, "extra")
    Dir.mkdir_p(command_cwd)
    Dir.mkdir_p(extra_root)

    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy_cwd: command_cwd,
      command_cwd: command_cwd,
      writable_roots: [extra_root],
      exclude_tmpdir_env_var: true,
    )

    paths.allow.includes?(File.realpath(command_cwd)).should be_true
    paths.allow.includes?(File.realpath(extra_root)).should be_true
    paths.deny.empty?.should be_true
    FileUtils.rm_rf(temp)
  end

  it "excludes TEMP/TMP paths when requested" do
    temp = "/tmp/windows-allow-no-tmp-#{Random.rand(100_000)}"
    command_cwd = File.join(temp, "workspace")
    temp_dir = File.join(temp, "temp")
    Dir.mkdir_p(command_cwd)
    Dir.mkdir_p(temp_dir)

    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy_cwd: command_cwd,
      command_cwd: command_cwd,
      writable_roots: [] of String,
      exclude_tmpdir_env_var: true,
      env_map: {"TEMP" => temp_dir}
    )

    paths.allow.includes?(File.realpath(command_cwd)).should be_true
    paths.allow.includes?(File.realpath(temp_dir)).should be_false
    paths.deny.empty?.should be_true
    FileUtils.rm_rf(temp)
  end

  it "includes TMP from process env when env_map omits it" do
    temp = "/tmp/windows-allow-tmp-fallback-#{Random.rand(100_000)}"
    workspace = File.join(temp, "workspace")
    tmp_dir = File.join(temp, "tmp-fallback")
    Dir.mkdir_p(workspace)
    Dir.mkdir_p(tmp_dir)

    previous_tmp = ENV["TMP"]?
    begin
      ENV["TMP"] = tmp_dir
      paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
        policy_cwd: workspace,
        command_cwd: workspace,
        exclude_tmpdir_env_var: false,
        env_map: Hash(String, String).new
      )

      paths.allow.includes?(File.realpath(tmp_dir)).should be_true
    ensure
      if previous_tmp
        ENV["TMP"] = previous_tmp
      else
        ENV.delete("TMP")
      end
      FileUtils.rm_rf(temp)
    end
  end

  it "denies .git dir and file entries inside writable roots" do
    temp = "/tmp/windows-allow-git-#{Random.rand(100_000)}"
    workspace_a = File.join(temp, "workspace-a")
    workspace_b = File.join(temp, "workspace-b")
    Dir.mkdir_p(File.join(workspace_a, ".git"))
    Dir.mkdir_p(workspace_b)
    File.write(File.join(workspace_b, ".git"), "gitdir: .git/worktrees/example")

    paths_a = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy_cwd: workspace_a,
      command_cwd: workspace_a,
      exclude_tmpdir_env_var: true,
    )
    paths_b = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy_cwd: workspace_b,
      command_cwd: workspace_b,
      exclude_tmpdir_env_var: true,
    )

    paths_a.deny.includes?(File.realpath(File.join(workspace_a, ".git"))).should be_true
    paths_b.deny.includes?(File.realpath(File.join(workspace_b, ".git"))).should be_true
    FileUtils.rm_rf(temp)
  end

  it "denies .codex and .agents inside writable roots" do
    temp = "/tmp/windows-allow-protected-#{Random.rand(100_000)}"
    workspace = File.join(temp, "workspace")
    Dir.mkdir_p(File.join(workspace, ".codex"))
    Dir.mkdir_p(File.join(workspace, ".agents"))

    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy_cwd: workspace,
      command_cwd: workspace,
      exclude_tmpdir_env_var: true,
    )

    paths.deny.includes?(File.realpath(File.join(workspace, ".codex"))).should be_true
    paths.deny.includes?(File.realpath(File.join(workspace, ".agents"))).should be_true
    FileUtils.rm_rf(temp)
  end

  it "computes allow/deny paths from workspace-write policy object" do
    temp = "/tmp/windows-allow-policy-object-#{Random.rand(100_000)}"
    workspace = File.join(temp, "workspace")
    extra = File.join(temp, "extra")
    Dir.mkdir_p(File.join(workspace, ".codex"))
    Dir.mkdir_p(extra)
    policy = Sandbox::Sandboxing::WindowsSandbox::Policy.workspace_write(
      writable_roots: [extra],
      exclude_tmpdir_env_var: true
    )

    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy,
      workspace,
      workspace,
      Hash(String, String).new
    )

    paths.allow.includes?(File.realpath(workspace)).should be_true
    paths.allow.includes?(File.realpath(extra)).should be_true
    paths.deny.includes?(File.realpath(File.join(workspace, ".codex"))).should be_true
    FileUtils.rm_rf(temp)
  end

  it "policy object tmp exclusion removes TEMP and TMP from allow roots" do
    temp = "/tmp/windows-allow-policy-tmp-exclusion-#{Random.rand(100_000)}"
    workspace = File.join(temp, "workspace")
    tmp_dir = File.join(temp, "tmp-dir")
    Dir.mkdir_p(workspace)
    Dir.mkdir_p(tmp_dir)

    policy = Sandbox::Sandboxing::WindowsSandbox::Policy.workspace_write(
      exclude_tmpdir_env_var: true
    )
    env = {"TEMP" => tmp_dir, "TMP" => tmp_dir}
    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy,
      workspace,
      workspace,
      env
    )

    paths.allow.includes?(File.realpath(workspace)).should be_true
    paths.allow.includes?(File.realpath(tmp_dir)).should be_false
    FileUtils.rm_rf(temp)
  end

  it "policy object exclude_slash_tmp omits /tmp root from allow paths" do
    temp = "/tmp/windows-allow-exclude-slash-tmp-#{Random.rand(100_000)}"
    workspace = File.join(temp, "workspace")
    Dir.mkdir_p(workspace)

    policy = Sandbox::Sandboxing::WindowsSandbox::Policy.workspace_write(
      exclude_slash_tmp: true
    )
    env = {"TMP" => "/tmp"}
    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy,
      workspace,
      workspace,
      env
    )

    paths.allow.includes?("/tmp").should be_false
    FileUtils.rm_rf(temp)
  end

  it "skips protected subdirs when missing" do
    temp = "/tmp/windows-allow-missing-protected-#{Random.rand(100_000)}"
    workspace = File.join(temp, "workspace")
    Dir.mkdir_p(workspace)

    paths = Sandbox::Sandboxing::WindowsSandbox.compute_allow_paths(
      policy_cwd: workspace,
      command_cwd: workspace,
      exclude_tmpdir_env_var: true,
    )

    paths.allow.size.should eq(1)
    paths.deny.empty?.should be_true
    FileUtils.rm_rf(temp)
  end

  it "path mask honors deny over allow" do
    allow = Set{"/tmp/workspace"}
    deny = Set{"/tmp/workspace/.git"}
    Sandbox::Sandboxing::WindowsSandbox.path_mask_allows(
      "/tmp/workspace/file.txt",
      allow,
      deny
    ).should be_true
    Sandbox::Sandboxing::WindowsSandbox.path_mask_allows(
      "/tmp/workspace/.git/config",
      allow,
      deny
    ).should be_false
  end

  it "path mask does not treat sibling paths as children" do
    allow = Set{"/tmp/workspace"}
    deny = Set(String).new
    Sandbox::Sandboxing::WindowsSandbox.path_mask_allows(
      "/tmp/workspace-other/file.txt",
      allow,
      deny
    ).should be_false
  end

  it "destination freshness uses size and mtime" do
    temp = "/tmp/windows-helper-fresh-#{Random.rand(100_000)}"
    source = File.join(temp, "source.exe")
    destination = File.join(temp, "destination.exe")
    Dir.mkdir_p(temp)

    File.write(destination, "same-size")
    sleep 1.second
    File.write(source, "same-size")
    Sandbox::Sandboxing::WindowsSandbox.destination_is_fresh(
      source,
      destination
    ).should be_false

    File.write(destination, "same-size")
    Sandbox::Sandboxing::WindowsSandbox.destination_is_fresh(
      source,
      destination
    ).should be_true
    FileUtils.rm_rf(temp)
  end

  it "copies missing destination for helper materialization" do
    temp = "/tmp/windows-helper-copy-missing-#{Random.rand(100_000)}"
    source = File.join(temp, "source.exe")
    destination = File.join(temp, "bin", "helper.exe")
    Dir.mkdir_p(temp)
    File.write(source, "runner-v1")

    outcome = Sandbox::Sandboxing::WindowsSandbox.copy_from_source_if_needed(source, destination)
    outcome.should eq(Sandbox::Sandboxing::WindowsSandbox::CopyOutcome::ReCopied)
    File.read(destination).should eq("runner-v1")
    FileUtils.rm_rf(temp)
  end

  it "reuses fresh destination for helper materialization" do
    temp = "/tmp/windows-helper-copy-reuse-#{Random.rand(100_000)}"
    source = File.join(temp, "source.exe")
    destination = File.join(temp, "bin", "helper.exe")
    Dir.mkdir_p(temp)
    File.write(source, "runner-v1")
    Sandbox::Sandboxing::WindowsSandbox.copy_from_source_if_needed(source, destination)

    outcome = Sandbox::Sandboxing::WindowsSandbox.copy_from_source_if_needed(source, destination)
    outcome.should eq(Sandbox::Sandboxing::WindowsSandbox::CopyOutcome::Reused)
    File.read(destination).should eq("runner-v1")
    FileUtils.rm_rf(temp)
  end

  it "builds helper bin dir under sandbox-bin" do
    codex_home = "/tmp/codex-home"
    actual = Sandbox::Sandboxing::WindowsSandbox.helper_bin_dir(codex_home)
    expected = "/tmp/codex-home/.sandbox-bin"
    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(actual).should eq(
      Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(expected)
    )
  end

  it "equivalent cwd spellings share workspace sid key" do
    workspace_by_cwd = {} of String => String
    first_sid = Sandbox::Sandboxing::WindowsSandbox.workspace_cap_sid_for_cwd(
      workspace_by_cwd,
      "C:\\Users\\Dev\\WorkspaceRoot"
    )
    second_sid = Sandbox::Sandboxing::WindowsSandbox.workspace_cap_sid_for_cwd(
      workspace_by_cwd,
      "c:/users/dev/workspaceroot"
    )

    first_sid.should eq(second_sid)
    workspace_by_cwd.size.should eq(1)
  end

  it "gathers path entries by list separator" do
    temp = "/tmp/windows-audit-path-separator-#{Random.rand(100_000)}"
    dir_a = File.join(temp, "Tools")
    dir_b = File.join(temp, "Bin")
    dir_space = File.join(temp, "Program Files")
    Dir.mkdir_p(dir_a)
    Dir.mkdir_p(dir_b)
    Dir.mkdir_p(dir_space)

    env_map = {
      "PATH" => "#{dir_a};#{dir_b};#{dir_space}",
    }
    candidates = Sandbox::Sandboxing::WindowsSandbox.gather_candidates(temp, env_map)

    candidates.includes?(File.realpath(dir_a)).should be_true
    candidates.includes?(File.realpath(dir_b)).should be_true
    candidates.includes?(File.realpath(dir_space)).should be_true
    FileUtils.rm_rf(temp)
  end

  it "audits world-writable directories from cwd and candidate roots" do
    temp = "/tmp/windows-audit-world-writable-#{Random.rand(100_000)}"
    cwd = File.join(temp, "cwd")
    writable_child = File.join(cwd, "world")
    safe_child = File.join(cwd, "safe")
    Dir.mkdir_p(writable_child)
    Dir.mkdir_p(safe_child)
    File.chmod(writable_child, 0o777)
    File.chmod(safe_child, 0o755)

    flagged = Sandbox::Sandboxing::WindowsSandbox.audit_everyone_writable(
      cwd,
      Hash(String, String).new
    )

    flagged.includes?(File.realpath(writable_child)).should be_true
    {% unless flag?(:win32) %}
      flagged.includes?(File.realpath(safe_child)).should be_false
    {% end %}
    FileUtils.rm_rf(temp)
  end

  it "applies world-writable scan and deny pass without raising" do
    temp = "/tmp/windows-audit-apply-#{Random.rand(100_000)}"
    cwd = File.join(temp, "cwd")
    codex_home = File.join(temp, "codex-home")
    suspicious = File.join(cwd, "world")
    Dir.mkdir_p(suspicious)
    File.chmod(suspicious, 0o777)

    Sandbox::Sandboxing::WindowsSandbox.apply_world_writable_scan_and_denies(
      cwd,
      Hash(String, String).new,
      "workspace-write",
      codex_home
    )
    FileUtils.rm_rf(temp)
  end

  it "hardens world-writable flagged paths outside workspace root" do
    temp = "/tmp/windows-audit-harden-#{Random.rand(100_000)}"
    cwd = File.join(temp, "workspace")
    outside = File.join(temp, "outside")
    inside = File.join(cwd, "inside")
    Dir.mkdir_p(outside)
    Dir.mkdir_p(inside)
    File.chmod(outside, 0o777)
    File.chmod(inside, 0o777)

    Sandbox::Sandboxing::WindowsSandbox.apply_capability_denies_for_world_writable(
      [outside, inside],
      "workspace-write",
      cwd,
      File.join(temp, "codex-home")
    )

    {% if flag?(:win32) %}
      # Windows ACL translation is backend-specific; crystal fallback should not crash.
      File.exists?(outside).should be_true
      File.exists?(inside).should be_true
    {% else %}
      File.info(outside).permissions.other_write?.should be_false
      # Workspace-root descendants are intentionally excluded.
      File.info(inside).permissions.other_write?.should be_true
    {% end %}
    FileUtils.rm_rf(temp)
  end

  it "reads and removes request file" do
    temp = "/tmp/windows-request-file-#{Random.rand(100_000)}"
    Dir.mkdir_p(temp)
    request_path = File.join(temp, "runner_request.json")
    File.write(request_path, %({"command":["cmd","/c","echo hi"]}))

    payload = Sandbox::Sandboxing::WindowsSandbox.read_request_file(request_path)
    payload.should contain(%("command"))
    File.exists?(request_path).should be_false
    FileUtils.rm_rf(temp)
  end

  it "creates cwd junction as passthrough path in crystal port" do
    cwd = "/tmp/windows-cwd-junction-#{Random.rand(100_000)}"
    Sandbox::Sandboxing::WindowsSandbox.create_cwd_junction(cwd).should eq(cwd)
  end

  it "dpapi protect and unprotect round trip" do
    secret = "token-#{Random.rand(100_000)}"
    protected_secret = Sandbox::Sandboxing::WindowsSandbox.protect(secret)
    protected_secret.should_not eq(secret)
    Sandbox::Sandboxing::WindowsSandbox.unprotect(protected_secret).should eq(secret)
  end

  it "builds sorted process env block with double-null termination" do
    env = {"b" => "2", "A" => "1"}
    block = Sandbox::Sandboxing::WindowsSandbox.make_env_block(env)
    block.should eq("A=1\0b=2\0\0")
  end

  it "read acl mutex helpers expose expected default states" do
    Sandbox::Sandboxing::WindowsSandbox.acquire_read_acl_mutex.should be_true
    Sandbox::Sandboxing::WindowsSandbox.read_acl_mutex_exists.should be_false
    guard = Sandbox::Sandboxing::WindowsSandbox::ReadAclMutexGuard.new
    guard.acquired?.should be_true
  end

  it "sandbox identity completion requires marker and users files" do
    temp = "/tmp/windows-sandbox-identity-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    FileUtils.mkdir_p(Sandbox::Sandboxing::WindowsSandbox.sandbox_dir(codex_home))
    FileUtils.mkdir_p(Sandbox::Sandboxing::WindowsSandbox.sandbox_secrets_dir(codex_home))

    Sandbox::Sandboxing::WindowsSandbox.sandbox_setup_is_complete(codex_home).should be_false
    File.write(Sandbox::Sandboxing::WindowsSandbox.setup_marker_path(codex_home), "{}")
    File.write(Sandbox::Sandboxing::WindowsSandbox.sandbox_users_path(codex_home), "{}")
    Sandbox::Sandboxing::WindowsSandbox.sandbox_setup_is_complete(codex_home).should be_true
    FileUtils.rm_rf(temp)
  end

  it "provisions sandbox users and resolves sid helpers" do
    {% if flag?(:win32) %}
      Sandbox::Sandboxing::WindowsSandbox.provision_sandbox_users.should be_true
      Sandbox::Sandboxing::WindowsSandbox.ensure_sandbox_users_group.should be_true
      Sandbox::Sandboxing::WindowsSandbox.ensure_sandbox_user("CodexSandboxOffline").should be_true
      sid = Sandbox::Sandboxing::WindowsSandbox.resolve_sandbox_users_group_sid
      sid.empty?.should be_false
      sid.starts_with?("S-1-").should be_true
    {% else %}
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.provision_sandbox_users
      end
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.resolve_sandbox_users_group_sid
      end
    {% end %}
  end

  it "converts SID bytes to string SID format" do
    sid = Sandbox::Sandboxing::WindowsSandbox.sid_bytes_to_psid(
      Bytes[
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x20, 0x00, 0x00, 0x00,
        0x20, 0x02, 0x00, 0x00,
      ]
    )
    sid.should eq("S-1-5-32-544")
  end

  it "rejects invalid SID byte payloads" do
    expect_raises(ArgumentError, /too short/) do
      Sandbox::Sandboxing::WindowsSandbox.sid_bytes_to_psid(Bytes[0x01, 0x01])
    end

    expect_raises(ArgumentError, /truncated/) do
      Sandbox::Sandboxing::WindowsSandbox.sid_bytes_to_psid(
        Bytes[
          0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
          0x20, 0x00, 0x00, 0x00,
        ]
      )
    end
  end

  it "setup_main_win_main reads and removes request payload" do
    temp = "/tmp/windows-setup-main-#{Random.rand(100_000)}"
    Dir.mkdir_p(temp)
    request_path = File.join(temp, "setup_request.json")
    File.write(request_path, %({"setup":"run"}))

    payload = Sandbox::Sandboxing::WindowsSandbox.setup_main_win_main(request_path)
    payload.should contain(%("setup"))
    File.exists?(request_path).should be_false
    FileUtils.rm_rf(temp)
  end

  it "exposes setup orchestrator path helpers under configurable sandbox home" do
    home_dir = "/tmp/sandbox-home-paths"
    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
      Sandbox::Sandboxing::WindowsSandbox.sandbox_dir(home_dir)
    ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/sandbox-home-paths/.sandbox"))
    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
      Sandbox::Sandboxing::WindowsSandbox.sandbox_bin_dir(home_dir)
    ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/sandbox-home-paths/.sandbox-bin"))
    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
      Sandbox::Sandboxing::WindowsSandbox.sandbox_secrets_dir(home_dir)
    ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/sandbox-home-paths/.sandbox-secrets"))
    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
      Sandbox::Sandboxing::WindowsSandbox.setup_marker_path(home_dir)
    ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/sandbox-home-paths/.sandbox/setup_marker.json"))
    Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
      Sandbox::Sandboxing::WindowsSandbox.sandbox_users_path(home_dir)
    ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/sandbox-home-paths/.sandbox-secrets/sandbox_users.json"))
  end

  it "uses configurable default sandbox home when no path is provided" do
    previous_home = Sandbox::Sandboxing::WindowsSandbox.sandbox_home
    begin
      Sandbox::Sandboxing::WindowsSandbox.sandbox_home = "/tmp/windows-default-home"
      Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
        Sandbox::Sandboxing::WindowsSandbox.sandbox_dir
      ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/windows-default-home/.sandbox"))
      Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(
        Sandbox::Sandboxing::WindowsSandbox.helper_bin_dir
      ).should eq(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key("/tmp/windows-default-home/.sandbox-bin"))
    ensure
      Sandbox::Sandboxing::WindowsSandbox.sandbox_home = previous_home
    end
  end

  it "uses configurable sandbox identity defaults" do
    previous_group = Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group
    previous_offline = Sandbox::Sandboxing::WindowsSandbox.offline_username
    previous_online = Sandbox::Sandboxing::WindowsSandbox.online_username
    begin
      Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group = "AgentSandboxUsers"
      Sandbox::Sandboxing::WindowsSandbox.offline_username = "AgentSandboxOffline"
      Sandbox::Sandboxing::WindowsSandbox.online_username = "AgentSandboxOnline"

      creds = Sandbox::Sandboxing::WindowsSandbox.require_logon_sandbox_creds
      creds.offline_username.should eq("AgentSandboxOffline")
      creds.online_username.should eq("AgentSandboxOnline")
      Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group.should eq("AgentSandboxUsers")
    ensure
      Sandbox::Sandboxing::WindowsSandbox.sandbox_users_group = previous_group
      Sandbox::Sandboxing::WindowsSandbox.offline_username = previous_offline
      Sandbox::Sandboxing::WindowsSandbox.online_username = previous_online
    end
  end

  it "setup orchestrator version helpers match current version" do
    Sandbox::Sandboxing::WindowsSandbox.version_matches(
      Sandbox::Sandboxing::WindowsSandbox::SETUP_VERSION
    ).should be_true
    Sandbox::Sandboxing::WindowsSandbox::SandboxUsersFile.new.version_matches.should be_true
    Sandbox::Sandboxing::WindowsSandbox::SetupMarker.new.version_matches.should be_true
  end

  it "setup refresh and elevated setup stubs are callable" do
    env = {"PATH" => "C:\\Windows\\System32"}
    {% if flag?(:win32) %}
      previous = ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"]?
      begin
        ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = "1"
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh(
          "workspace-write",
          "/tmp",
          "/tmp",
          env,
          "/tmp/codex-home-stub"
        )
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh_with_extra_read_roots(
          "workspace-write",
          "/tmp",
          "/tmp",
          env,
          "/tmp/codex-home-stub",
          ["/tmp"]
        )
        Sandbox::Sandboxing::WindowsSandbox.run_elevated_setup(
          "workspace-write",
          "/tmp",
          "/tmp",
          env,
          "/tmp/codex-home-stub"
        )
      ensure
        if previous
          ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = previous
        else
          ENV.delete("SBX_WINDOWS_ALLOW_INSECURE_FALLBACK")
        end
      end
    {% else %}
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh(
          "workspace-write",
          "/tmp",
          "/tmp",
          env,
          "/tmp/codex-home-stub"
        )
      end
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh_with_extra_read_roots(
          "workspace-write",
          "/tmp",
          "/tmp",
          env,
          "/tmp/codex-home-stub",
          ["/tmp"]
        )
      end
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.run_elevated_setup(
          "workspace-write",
          "/tmp",
          "/tmp",
          env,
          "/tmp/codex-home-stub"
        )
      end
    {% end %}
  end

  it "setup refresh writes setup marker and sandbox users artifacts" do
    temp = "/tmp/windows-setup-refresh-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    workspace = File.join(temp, "workspace")
    Dir.mkdir_p(workspace)

    {% if flag?(:win32) %}
      previous = ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"]?
      begin
        ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = "1"
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh(
          "workspace-write",
          workspace,
          workspace,
          Hash(String, String).new,
          codex_home
        )
      ensure
        if previous
          ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = previous
        else
          ENV.delete("SBX_WINDOWS_ALLOW_INSECURE_FALLBACK")
        end
      end

      File.exists?(Sandbox::Sandboxing::WindowsSandbox.setup_marker_path(codex_home)).should be_true
      File.exists?(Sandbox::Sandboxing::WindowsSandbox.sandbox_users_path(codex_home)).should be_true
    {% else %}
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh(
          "workspace-write",
          workspace,
          workspace,
          Hash(String, String).new,
          codex_home
        )
      end
    {% end %}
    FileUtils.rm_rf(temp)
  end

  it "setup refresh with extra read roots persists existing extra roots" do
    temp = "/tmp/windows-setup-refresh-extra-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    workspace = File.join(temp, "workspace")
    extra = File.join(temp, "extra")
    missing = File.join(temp, "missing")
    Dir.mkdir_p(workspace)
    Dir.mkdir_p(extra)

    {% if flag?(:win32) %}
      previous = ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"]?
      begin
        ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = "1"
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh_with_extra_read_roots(
          "workspace-write",
          workspace,
          workspace,
          Hash(String, String).new,
          codex_home,
          [extra, missing]
        )
      ensure
        if previous
          ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = previous
        else
          ENV.delete("SBX_WINDOWS_ALLOW_INSECURE_FALLBACK")
        end
      end

      roots_path = File.join(Sandbox::Sandboxing::WindowsSandbox.sandbox_dir(codex_home), "read_roots.json")
      File.exists?(roots_path).should be_true
      roots = Array(String).from_json(File.read(roots_path))
      canonical_roots = roots.map { |root| Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(root) }
      canonical_roots.includes?(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(extra)).should be_true
      canonical_roots.includes?(Sandbox::Sandboxing::WindowsSandbox.canonical_path_key(missing)).should be_false
    {% else %}
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.run_setup_refresh_with_extra_read_roots(
          "workspace-write",
          workspace,
          workspace,
          Hash(String, String).new,
          codex_home,
          [extra, missing]
        )
      end
    {% end %}
    FileUtils.rm_rf(temp)
  end

  it "winutil helpers expose deterministic formatting" do
    Sandbox::Sandboxing::WindowsSandbox.format_last_error(5).should eq("Windows error 5")
    Sandbox::Sandboxing::WindowsSandbox.quote_windows_arg("plain").should eq("plain")
    Sandbox::Sandboxing::WindowsSandbox.quote_windows_arg("has space").should eq(%("has space"))
    Sandbox::Sandboxing::WindowsSandbox.quote_windows_arg(%(quote"here)).should eq(%("quote\\"here"))
    Sandbox::Sandboxing::WindowsSandbox.quote_windows_arg(%(path with trailing\\)).should eq(%("path with trailing\\\\"))
    Sandbox::Sandboxing::WindowsSandbox.quote_windows_arg(%(mix\\"q)).should eq(%("mix\\\\\\"q"))
    Sandbox::Sandboxing::WindowsSandbox.string_from_sid_bytes(
      Bytes[
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x20, 0x00, 0x00, 0x00,
        0x20, 0x02, 0x00, 0x00,
      ]
    ).should eq("S-1-5-32-544")
  end

  it "detects command cwd roots" do
    Sandbox::Sandboxing::WindowsSandbox.is_command_cwd_root("/").should be_true
    Sandbox::Sandboxing::WindowsSandbox.is_command_cwd_root("C:\\").should be_true
    Sandbox::Sandboxing::WindowsSandbox.is_command_cwd_root("/tmp/not-root").should be_false
  end

  it "hide users helpers are callable no-ops in crystal port" do
    temp = "/tmp/windows-hide-users-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    sandbox_dir = Sandbox::Sandboxing::WindowsSandbox.sandbox_dir(codex_home)
    Dir.mkdir_p(sandbox_dir)

    previous_home = ENV["HOME"]?
    begin
      ENV["HOME"] = temp
      Sandbox::Sandboxing::WindowsSandbox.hide_current_user_profile_dir(codex_home)
    ensure
      if previous_home
        ENV["HOME"] = previous_home
      else
        ENV.delete("HOME")
      end
    end

    Sandbox::Sandboxing::WindowsSandbox.hide_newly_created_users(
      ["CodexSandboxOffline", "CodexSandboxOnline"],
      codex_home
    )

    profile_file = File.join(sandbox_dir, "hidden_profile_dirs.json")
    users_file = File.join(sandbox_dir, "hidden_users.json")
    File.exists?(profile_file).should be_true
    File.exists?(users_file).should be_true
    Array(String).from_json(File.read(users_file)).should contain("CodexSandboxOffline")
    Array(String).from_json(File.read(users_file)).should contain("CodexSandboxOnline")
    FileUtils.rm_rf(temp)
  end

  it "profile read roots excludes configured top-level entries" do
    temp = "/tmp/windows-profile-roots-#{Random.rand(100_000)}"
    allowed_dir = File.join(temp, "Documents")
    allowed_file = File.join(temp, ".gitconfig")
    excluded_dir = File.join(temp, ".ssh")
    excluded_case_variant = File.join(temp, ".AWS")
    Dir.mkdir_p(allowed_dir)
    File.write(allowed_file, "safe")
    Dir.mkdir_p(excluded_dir)
    Dir.mkdir_p(excluded_case_variant)

    roots = Sandbox::Sandboxing::WindowsSandbox.profile_read_roots(temp).to_set
    roots.includes?(allowed_dir).should be_true
    roots.includes?(allowed_file).should be_true
    roots.includes?(excluded_dir).should be_false
    roots.includes?(excluded_case_variant).should be_false
    FileUtils.rm_rf(temp)
  end

  it "profile read roots falls back to profile root when enumeration fails" do
    temp = "/tmp/windows-profile-missing-#{Random.rand(100_000)}"
    missing_profile = File.join(temp, "missing-user-profile")

    roots = Sandbox::Sandboxing::WindowsSandbox.profile_read_roots(missing_profile)
    roots.should eq([missing_profile])
  end

  it "gather read roots includes helper bin dir" do
    temp = "/tmp/windows-gather-read-roots-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    command_cwd = File.join(temp, "workspace")
    Dir.mkdir_p(command_cwd)

    roots = Sandbox::Sandboxing::WindowsSandbox.gather_read_roots(command_cwd, codex_home)
    expected = File.realpath(Sandbox::Sandboxing::WindowsSandbox.helper_bin_dir(codex_home))
    roots.includes?(expected).should be_true
    FileUtils.rm_rf(temp)
  end

  it "copies runner into shared bin dir" do
    temp = "/tmp/windows-helper-copy-runner-#{Random.rand(100_000)}"
    codex_home = File.join(temp, "codex-home")
    source = File.join(temp, "codex-command-runner.exe")
    destination = File.join(
      Sandbox::Sandboxing::WindowsSandbox.helper_bin_dir(codex_home),
      "codex-command-runner.exe"
    )
    Dir.mkdir_p(temp)
    File.write(source, "runner")

    outcome = Sandbox::Sandboxing::WindowsSandbox.copy_from_source_if_needed(source, destination)
    outcome.should eq(Sandbox::Sandboxing::WindowsSandbox::CopyOutcome::ReCopied)
    File.read(destination).should eq("runner")
    FileUtils.rm_rf(temp)
  end

  it "applies network block when workspace-write access is disabled" do
    policy = Sandbox::Sandboxing::WindowsSandbox::Policy.workspace_write(network_access: false)
    Sandbox::Sandboxing::WindowsSandbox.should_apply_network_block(policy).should be_true
  end

  it "skips network block when workspace-write access is enabled" do
    policy = Sandbox::Sandboxing::WindowsSandbox::Policy.workspace_write(network_access: true)
    Sandbox::Sandboxing::WindowsSandbox.should_apply_network_block(policy).should be_false
  end

  it "applies network block for read-only policy" do
    policy = Sandbox::Sandboxing::WindowsSandbox::Policy.read_only
    Sandbox::Sandboxing::WindowsSandbox.should_apply_network_block(policy).should be_true
  end

  it "returns a default capture result shape" do
    result = Sandbox::Sandboxing::WindowsSandbox::CaptureResult.new
    result.exit_code.should eq(1)
    result.timed_out?.should be_false
  end

  it "captures command output for workspace-write policy" do
    {% if flag?(:win32) %}
      previous = ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"]?
      result = begin
        ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = "1"
        Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_capture(
          "workspace-write",
          ["cmd", "/c", "echo", "hello"],
          Dir.current,
          Hash(String, String).new
        )
      ensure
        if previous
          ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = previous
        else
          ENV.delete("SBX_WINDOWS_ALLOW_INSECURE_FALLBACK")
        end
      end
      result.exit_code.should eq(0)
      String.new(result.stdout).includes?("hello").should be_true
    {% else %}
      result = Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_capture(
        "workspace-write",
        ["/bin/echo", "hello"],
        "/tmp",
        Hash(String, String).new
      )
      result.exit_code.should_not eq(0)
      String.new(result.stderr).includes?("Windows sandbox is only available on Windows").should be_true
    {% end %}
  end

  it "marks capture as timed out when timeout is reached" do
    {% if flag?(:win32) %}
      previous = ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"]?
      result = begin
        ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = "1"
        Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_capture(
          "workspace-write",
          ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 1"],
          Dir.current,
          Hash(String, String).new,
          timeout_ms: 10
        )
      ensure
        if previous
          ENV["SBX_WINDOWS_ALLOW_INSECURE_FALLBACK"] = previous
        else
          ENV.delete("SBX_WINDOWS_ALLOW_INSECURE_FALLBACK")
        end
      end
      result.timed_out?.should be_true
      result.exit_code.should eq(192)
    {% else %}
      result = Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_capture(
        "workspace-write",
        ["/bin/sleep", "1"],
        "/tmp",
        Hash(String, String).new,
        timeout_ms: 10
      )
      result.timed_out?.should be_false
      result.exit_code.should_not eq(0)
    {% end %}
  end

  {% unless flag?(:win32) %}
    it "captures command failure on non-windows hosts without crashing" do
      result = Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_capture(
        "read-only",
        ["cmd", "/c", "echo", "hi"],
        "/tmp",
        Hash(String, String).new
      )
      result.exit_code.should_not eq(0)
      String.new(result.stderr).empty?.should be_false
    end

    it "legacy preflight errors on non-windows hosts" do
      expect_raises(Exception, /Windows sandbox is only available on Windows/) do
        Sandbox::Sandboxing::WindowsSandbox.run_windows_sandbox_legacy_preflight(
          Sandbox::Sandboxing::WindowsSandbox::Policy.read_only
        )
      end
    end
  {% end %}
end

describe Sandbox::Sandboxing::MacosPermissions do
  it "merges extension fields permissively" do
    base = Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
      macos_preferences: Sandbox::Sandboxing::MacosPreferencesPermission::ReadOnly,
      macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Calendar"]),
      macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadOnly
    )
    requested = Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
      macos_preferences: Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite,
      macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Notes", "com.apple.Calendar"]),
      macos_launch_services: true,
      macos_accessibility: true,
      macos_calendar: true,
      macos_reminders: true,
      macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadWrite
    )

    merged = Sandbox::Sandboxing::MacosPermissions.merge_macos_seatbelt_profile_extensions(
      base,
      requested
    )

    merged.should eq(
      Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
        macos_preferences: Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite,
        macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Calendar", "com.apple.Notes"]),
        macos_launch_services: true,
        macos_accessibility: true,
        macos_calendar: true,
        macos_reminders: true,
        macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadWrite
      )
    )
  end

  it "merges preferences and contacts without downgrade" do
    merged_preferences = Sandbox::Sandboxing::MacosPermissions.union_macos_preferences_permission(
      Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite,
      Sandbox::Sandboxing::MacosPreferencesPermission::ReadOnly
    )
    merged_contacts = Sandbox::Sandboxing::MacosPermissions.union_macos_contacts_permission(
      Sandbox::Sandboxing::MacosContactsPermission::ReadWrite,
      Sandbox::Sandboxing::MacosContactsPermission::ReadOnly
    )

    merged_preferences.should eq(Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite)
    merged_contacts.should eq(Sandbox::Sandboxing::MacosContactsPermission::ReadWrite)
  end

  it "treats automation all as dominant union" do
    merged = Sandbox::Sandboxing::MacosPermissions.union_macos_automation_permission(
      Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Notes"]),
      Sandbox::Sandboxing::MacosAutomationPermission.all
    )
    merged.kind.should eq(Sandbox::Sandboxing::MacosAutomationKind::All)
  end

  it "intersects automation bundle ids" do
    intersected = Sandbox::Sandboxing::MacosPermissions.intersect_macos_automation_permission(
      Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Notes", "com.apple.Calendar"]),
      Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Notes"])
    )

    intersected.should eq(
      Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(["com.apple.Notes"])
    )
  end
end

{% if flag?(:darwin) %}
  describe Sandbox::Sandboxing::SeatbeltPermissions do
    it "default extensions include preferences read but not write" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.default
      )
      policy.policy.includes?("(allow user-preference-read)").should be_true
      policy.policy.includes?("(allow user-preference-write)").should be_false
    end

    it "automation bundle ids are normalized and scoped" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.bundle_ids(
            [" com.apple.Notes ", "com.apple.Calendar", "com.apple.Notes"]
          )
        )
      )

      policy.policy.includes?("(appleevent-destination \"com.apple.Calendar\")").should be_true
      policy.policy.includes?("(appleevent-destination \"com.apple.Notes\")").should be_true
    end

    it "preferences read-write emits write clauses" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_preferences: Sandbox::Sandboxing::MacosPreferencesPermission::ReadWrite
        )
      )
      policy.policy.includes?("(allow user-preference-write)").should be_true
      policy.policy.includes?("ipc-posix-shm-write-create").should be_true
    end

    it "automation all emits unscoped appleevent send" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_automation: Sandbox::Sandboxing::MacosAutomationPermission.all
        )
      )
      policy.policy.includes?("(allow appleevent-send)").should be_true
      policy.policy.includes?("com.apple.coreservices.appleevents").should be_true
    end

    it "launch services emit lookup and lsopen clauses" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_launch_services: true
        )
      )
      policy.policy.includes?("com.apple.coreservices.launchservicesd").should be_true
      policy.policy.includes?("(allow lsopen)").should be_true
    end

    it "accessibility, calendar, and reminders emit mach lookups" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_accessibility: true,
          macos_calendar: true,
          macos_reminders: true
        )
      )
      policy.policy.includes?("com.apple.axserver").should be_true
      policy.policy.includes?("com.apple.CalendarAgent").should be_true
      policy.policy.includes?("com.apple.remindd").should be_true
    end

    it "contacts read-only omits securityd clause" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadOnly
        )
      )
      policy.policy.includes?("com.apple.contactsd.persistence").should be_true
      policy.policy.includes?("com.apple.securityd.xpc").should be_false
    end

    it "contacts read-write adds securityd clause and addressbook param" do
      policy = Sandbox::Sandboxing::SeatbeltPermissions.build_seatbelt_extensions(
        Sandbox::Sandboxing::MacosSeatbeltProfileExtensions.new(
          macos_contacts: Sandbox::Sandboxing::MacosContactsPermission::ReadWrite
        )
      )

      policy.policy.includes?("com.apple.securityd.xpc").should be_true
      policy.dir_params.any? { |(key, _)| key == "ADDRESSBOOK_DIR" }.should be_true
    end
  end
{% end %}

{% if flag?(:darwin) %}
  describe Sandbox::Sandboxing::MacosSeatbelt do
    it "base policy allows node cpu sysctls" do
      profile = Sandbox::Sandboxing::MacosSeatbelt.profile_for(
        Sandbox::Sandboxing::FileSystemSandboxPolicy.restricted,
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted
      )

      profile.includes?(%(sysctl-name "machdep.cpu.brand_string")).should be_true
      profile.includes?(%(sysctl-name "hw.model")).should be_true
    end

    it "extracts loopback proxy ports from env" do
      env = {
        "HTTP_PROXY"  => "http://127.0.0.1:43128",
        "HTTPS_PROXY" => "http://example.com:3128",
        "ALL_PROXY"   => "socks5h://localhost:8080",
      }
      ports = Sandbox::Sandboxing::MacosSeatbelt.proxy_loopback_ports_from_env(env)
      ports.should eq([8080, 43128])
    end

    it "rejects relative paths during seatbelt path normalization" do
      Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(
        "relative.sock"
      ).should be_nil
    end

    it "uses stable unix socket param names from sorted unique paths" do
      proxy = Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
        unix_domain_socket_policy_kind: Sandbox::Sandboxing::MacosSeatbelt::UnixDomainSocketPolicyKind::Restricted,
        allowed_unix_socket_paths: ["/tmp/b.sock", "/tmp/a.sock", "/tmp/a.sock"]
      )
      params = Sandbox::Sandboxing::MacosSeatbelt.unix_socket_dir_params(proxy)
      params.should eq(
        [
          {"UNIX_SOCKET_PATH_0", "/tmp/a.sock"},
          {"UNIX_SOCKET_PATH_1", "/tmp/b.sock"},
        ]
      )
    end

    it "emits newline terminated unix socket policies" do
      allowlist = Sandbox::Sandboxing::MacosSeatbelt.unix_socket_policy(
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          unix_domain_socket_policy_kind: Sandbox::Sandboxing::MacosSeatbelt::UnixDomainSocketPolicyKind::Restricted,
          allowed_unix_socket_paths: ["/tmp/example.sock"]
        )
      )
      allowall = Sandbox::Sandboxing::MacosSeatbelt.unix_socket_policy(
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          unix_domain_socket_policy_kind: Sandbox::Sandboxing::MacosSeatbelt::UnixDomainSocketPolicyKind::AllowAll
        )
      )

      allowlist.ends_with?('\n').should be_true
      allowall.ends_with?('\n').should be_true
    end

    it "routes network through proxy ports in restricted mode" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        false,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          ports: [43128, 48081],
          has_proxy_config: true
        )
      )

      policy.includes?(
        %(allow network-outbound (remote ip "localhost:43128"))
      ).should be_true
      policy.includes?(
        %(allow network-outbound (remote ip "localhost:48081"))
      ).should be_true
      policy.includes?("\n(allow network-outbound)\n").should be_false
      policy.includes?(%(allow network-bind (local ip "localhost:*"))).should be_false
      policy.includes?(%(allow network-inbound (local ip "localhost:*"))).should be_false
    end

    it "allows loopback binding only when explicitly enabled" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        false,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          ports: [43128],
          has_proxy_config: true,
          allow_local_binding: true
        )
      )

      policy.includes?(%(allow network-bind (local ip "localhost:*"))).should be_true
      policy.includes?(%(allow network-inbound (local ip "localhost:*"))).should be_true
      policy.includes?(%(allow network-outbound (remote ip "localhost:*"))).should be_true
      policy.includes?("\n(allow network-outbound)\n").should be_false
    end

    it "keeps restricted policy when proxy config exists without loopback ports" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        false,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          has_proxy_config: true
        )
      )

      policy.includes?("(socket-domain AF_SYSTEM)").should be_true
      policy.includes?("\n(allow network-outbound)\n").should be_false
      policy.includes?(%(allow network-outbound (remote ip "localhost:))).should be_false
    end

    it "keeps restricted policy for managed network without proxy config" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        true,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new
      )

      policy.includes?("(socket-domain AF_SYSTEM)").should be_true
      policy.includes?("\n(allow network-outbound)\n").should be_false
    end

    it "allows all unix sockets when configured" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        false,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          ports: [43128],
          has_proxy_config: true,
          unix_domain_socket_policy_kind: Sandbox::Sandboxing::MacosSeatbelt::UnixDomainSocketPolicyKind::AllowAll
        )
      )

      policy.includes?("(allow system-socket (socket-domain AF_UNIX))").should be_true
      policy.includes?("(allow network-bind (local unix-socket))").should be_true
      policy.includes?("(allow network-outbound (remote unix-socket))").should be_true
    end

    it "allowlists unix socket paths when configured" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Restricted,
        false,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          ports: [43128],
          has_proxy_config: true,
          unix_domain_socket_policy_kind: Sandbox::Sandboxing::MacosSeatbelt::UnixDomainSocketPolicyKind::Restricted,
          allowed_unix_socket_paths: ["/tmp/example.sock"]
        )
      )

      policy.includes?("(allow system-socket (socket-domain AF_UNIX))").should be_true
      policy.includes?(
        %(allow network-bind (local unix-socket (subpath (param "UNIX_SOCKET_PATH_0"))))
      ).should be_true
      policy.includes?(
        %(allow network-outbound (remote unix-socket (subpath (param "UNIX_SOCKET_PATH_0"))))
      ).should be_true
    end

    it "keeps proxy-only behavior when full network policy has proxy config" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.dynamic_network_policy(
        Sandbox::Sandboxing::NetworkSandboxPolicy::Enabled,
        false,
        Sandbox::Sandboxing::MacosSeatbelt::ProxyPolicyInputs.new(
          ports: [43128],
          has_proxy_config: true
        )
      )

      policy.includes?(%(allow network-outbound (remote ip "localhost:43128"))).should be_true
      policy.includes?("\n(allow network-outbound)\n").should be_false
      policy.includes?("\n(allow network-inbound)\n").should be_false
    end

    it "detects read-only .git and .codex protected subpaths in writable root" do
      temp = "/tmp/macos-seatbelt-protected-subpaths-#{Random.rand(100_000)}"
      root = File.join(temp, "workspace")
      git = File.join(root, ".git")
      codex = File.join(root, ".codex")
      Dir.mkdir_p(git)
      Dir.mkdir_p(codex)

      paths = Sandbox::Sandboxing::MacosSeatbelt.protected_git_codex_subpaths(root)
      expected = [
        Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(codex),
        Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(git),
      ].compact
      expected.sort!
      paths.should eq(expected)
      FileUtils.rm_rf(temp)
    end

    it "detects read-only git pointer target path from .git file" do
      temp = "/tmp/macos-seatbelt-git-pointer-#{Random.rand(100_000)}"
      root = File.join(temp, "worktree")
      actual_gitdir = File.join(root, "actual-gitdir")
      dot_git = File.join(root, ".git")
      Dir.mkdir_p(actual_gitdir)
      Dir.mkdir_p(root)
      File.write(dot_git, "gitdir: #{actual_gitdir}\n")

      paths = Sandbox::Sandboxing::MacosSeatbelt.protected_git_codex_subpaths(root)
      paths.includes?(
        Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(dot_git)
      ).should be_true
      paths.includes?(
        Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(actual_gitdir)
      ).should be_true
      FileUtils.rm_rf(temp)
    end

    it "detects protected subpaths when cwd itself is a git repo" do
      temp = "/tmp/macos-seatbelt-cwd-git-repo-#{Random.rand(100_000)}"
      cwd = File.join(temp, "repo")
      dot_git = File.join(cwd, ".git")
      dot_codex = File.join(cwd, ".codex")
      Dir.mkdir_p(dot_git)
      Dir.mkdir_p(dot_codex)

      paths = Sandbox::Sandboxing::MacosSeatbelt.protected_git_codex_subpaths(cwd)
      paths.includes?(
        Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(dot_git)
      ).should be_true
      paths.includes?(
        Sandbox::Sandboxing::MacosSeatbelt.normalize_path_for_sandbox(dot_codex)
      ).should be_true
      FileUtils.rm_rf(temp)
    end

    it "excludes unreadable paths from full disk read and write carveout policy" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.unreadable_root_carveout_policy(
        ["/tmp/codex-unreadable"]
      )
      policy.includes?(%(require-not (subpath "/tmp/codex-unreadable"))).should be_true
    end

    it "excludes unreadable paths from readable roots carveout policy" do
      policy = Sandbox::Sandboxing::MacosSeatbelt.unreadable_root_carveout_policy(
        ["/tmp/codex-readable/private"]
      )
      policy.includes?(%(require-not (subpath "/tmp/codex-readable/private"))).should be_true
    end

    it "legacy workspace write nested readable root stays writable" do
      Sandbox::Sandboxing::MacosSeatbelt.legacy_workspace_write_nested_readable_root_stays_writable?(
        "/tmp/workspace",
        "/tmp/workspace/docs"
      ).should be_true
    end
  end
{% end %}
