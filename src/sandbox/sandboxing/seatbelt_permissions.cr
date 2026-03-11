module Sandbox
  module Sandboxing
    module SeatbeltPermissions
      struct SeatbeltExtensionPolicy
        getter policy : String
        getter dir_params : Array({String, String})

        def initialize(
          @policy : String = "",
          @dir_params : Array({String, String}) = [] of {String, String},
        )
        end
      end

      def self.build_seatbelt_extensions(
        extensions : MacosSeatbeltProfileExtensions,
      ) : SeatbeltExtensionPolicy
        normalized = normalized_extensions(extensions)
        clauses = [] of String
        dir_params = [] of {String, String}

        append_preferences_clauses(clauses, normalized.macos_preferences)
        append_automation_clauses(clauses, normalized.macos_automation)
        append_launch_services_clauses(clauses, normalized)
        append_contacts_clauses(clauses, dir_params, normalized.macos_contacts)

        return SeatbeltExtensionPolicy.new if clauses.empty?

        SeatbeltExtensionPolicy.new(
          policy: "; macOS permission profile extensions\n#{clauses.join("\n")}\n",
          dir_params: dir_params
        )
      end

      private def self.normalized_extensions(
        extensions : MacosSeatbeltProfileExtensions,
      ) : MacosSeatbeltProfileExtensions
        normalized_automation = case extensions.macos_automation.kind
                                in .bundle_ids?
                                  ids = normalize_bundle_ids(extensions.macos_automation.bundle_ids)
                                  ids.empty? ? MacosAutomationPermission.none : MacosAutomationPermission.bundle_ids(ids)
                                in .none?, .all?
                                  extensions.macos_automation
                                end

        MacosSeatbeltProfileExtensions.new(
          macos_preferences: extensions.macos_preferences,
          macos_automation: normalized_automation,
          macos_launch_services: extensions.macos_launch_services?,
          macos_accessibility: extensions.macos_accessibility?,
          macos_calendar: extensions.macos_calendar?,
          macos_reminders: extensions.macos_reminders?,
          macos_contacts: extensions.macos_contacts
        )
      end

      private def self.append_preferences_clauses(
        clauses : Array(String),
        permission : MacosPreferencesPermission,
      ) : Nil
        return if permission.none?

        clauses << "(allow ipc-posix-shm-read* (ipc-posix-name-prefix \"apple.cfprefs.\"))"
        clauses << "(allow mach-lookup (global-name \"com.apple.cfprefsd.daemon\") (global-name \"com.apple.cfprefsd.agent\") (local-name \"com.apple.cfprefsd.agent\"))"
        clauses << "(allow user-preference-read)"

        return unless permission.read_write?

        clauses << "(allow user-preference-write)"
        clauses << "(allow ipc-posix-shm-write-data (ipc-posix-name-prefix \"apple.cfprefs.\"))"
        clauses << "(allow ipc-posix-shm-write-create (ipc-posix-name-prefix \"apple.cfprefs.\"))"
      end

      private def self.append_automation_clauses(
        clauses : Array(String),
        permission : MacosAutomationPermission,
      ) : Nil
        return if permission.none?

        clauses << "(allow mach-lookup (global-name \"com.apple.coreservices.appleevents\"))"
        if permission.all?
          clauses << "(allow appleevent-send)"
          return
        end

        destinations = permission.bundle_ids.map { |bundle_id| %(    (appleevent-destination "#{bundle_id}")) }.join("\n")
        clauses << "(allow appleevent-send\n#{destinations}\n)"
      end

      private def self.append_launch_services_clauses(
        clauses : Array(String),
        extensions : MacosSeatbeltProfileExtensions,
      ) : Nil
        if extensions.macos_launch_services?
          clauses << "(allow mach-lookup (global-name \"com.apple.coreservices.launchservicesd\") (global-name \"com.apple.lsd.mapdb\") (global-name \"com.apple.coreservices.quarantine-resolver\") (global-name \"com.apple.lsd.modifydb\"))"
          clauses << "(allow lsopen)"
        end

        clauses << "(allow mach-lookup (local-name \"com.apple.axserver\"))" if extensions.macos_accessibility?
        clauses << "(allow mach-lookup (global-name \"com.apple.CalendarAgent\"))" if extensions.macos_calendar?
        clauses << "(allow mach-lookup (global-name \"com.apple.CalendarAgent\") (global-name \"com.apple.remindd\"))" if extensions.macos_reminders?
      end

      private def self.append_contacts_clauses(
        clauses : Array(String),
        dir_params : Array({String, String}),
        contacts_permission : MacosContactsPermission,
      ) : Nil
        return if contacts_permission.none?

        if contacts_permission.read_only?
          clauses << "(allow file-read* file-test-existence (subpath \"/System/Library/Address Book Plug-Ins\") (subpath (param \"ADDRESSBOOK_DIR\")))"
          clauses << "(allow mach-lookup (global-name \"com.apple.tccd\") (global-name \"com.apple.tccd.system\") (global-name \"com.apple.contactsd.persistence\") (global-name \"com.apple.AddressBook.ContactsAccountsService\") (global-name \"com.apple.contacts.account-caching\") (global-name \"com.apple.accountsd.accountmanager\"))"
        else
          clauses << "(allow file-read* file-write* (subpath \"/System/Library/Address Book Plug-Ins\") (subpath (param \"ADDRESSBOOK_DIR\")) (subpath \"/var/folders\") (subpath \"/private/var/folders\"))"
          clauses << "(allow mach-lookup (global-name \"com.apple.tccd\") (global-name \"com.apple.tccd.system\") (global-name \"com.apple.contactsd.persistence\") (global-name \"com.apple.AddressBook.ContactsAccountsService\") (global-name \"com.apple.contacts.account-caching\") (global-name \"com.apple.accountsd.accountmanager\") (global-name \"com.apple.securityd.xpc\"))"
        end

        if addressbook_dir = addressbook_dir()
          dir_params << {"ADDRESSBOOK_DIR", addressbook_dir}
        end
      end

      private def self.addressbook_dir : String?
        ENV["HOME"]?.try do |home|
          "#{home}/Library/Application Support/AddressBook"
        end
      end

      private def self.normalize_bundle_ids(bundle_ids : Array(String)) : Array(String)
        normalized = bundle_ids
          .map(&.strip)
          .select { |bundle_id| valid_bundle_id?(bundle_id) }
        normalized.uniq!
        normalized.sort!
        normalized
      end

      private def self.valid_bundle_id?(bundle_id : String) : Bool
        return false if bundle_id.size < 3 || !bundle_id.includes?('.')
        bundle_id.each_char.all? { |char| char.alphanumeric? || char.in?({'.', '-', '_'}) }
      end
    end
  end
end
