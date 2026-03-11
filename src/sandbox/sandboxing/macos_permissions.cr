module Sandbox
  module Sandboxing
    enum MacosPreferencesPermission
      None
      ReadOnly
      ReadWrite
    end

    enum MacosContactsPermission
      None
      ReadOnly
      ReadWrite
    end

    enum MacosAutomationKind
      None
      All
      BundleIds
    end

    struct MacosAutomationPermission
      getter kind : MacosAutomationKind
      getter bundle_ids : Array(String)

      def initialize(
        @kind : MacosAutomationKind = MacosAutomationKind::None,
        @bundle_ids : Array(String) = [] of String,
      )
      end

      def self.none : self
        new(MacosAutomationKind::None)
      end

      def self.all : self
        new(MacosAutomationKind::All)
      end

      def self.bundle_ids(ids : Array(String)) : self
        uniq = ids.uniq
        uniq.sort!
        uniq.empty? ? none : new(MacosAutomationKind::BundleIds, uniq)
      end

      def none? : Bool
        kind.none?
      end

      def all? : Bool
        kind.all?
      end
    end

    struct MacosSeatbeltProfileExtensions
      getter macos_preferences : MacosPreferencesPermission
      getter macos_automation : MacosAutomationPermission
      getter? macos_launch_services : Bool
      getter? macos_accessibility : Bool
      getter? macos_calendar : Bool
      getter? macos_reminders : Bool
      getter macos_contacts : MacosContactsPermission

      def initialize(
        @macos_preferences : MacosPreferencesPermission = MacosPreferencesPermission::ReadOnly,
        @macos_automation : MacosAutomationPermission = MacosAutomationPermission.none,
        @macos_launch_services : Bool = false,
        @macos_accessibility : Bool = false,
        @macos_calendar : Bool = false,
        @macos_reminders : Bool = false,
        @macos_contacts : MacosContactsPermission = MacosContactsPermission::None,
      )
      end

      def self.default : self
        new
      end
    end

    module MacosPermissions
      def self.merge_macos_seatbelt_profile_extensions(
        base : MacosSeatbeltProfileExtensions?,
        permissions : MacosSeatbeltProfileExtensions?,
      ) : MacosSeatbeltProfileExtensions?
        return base unless permissions
        return permissions unless base

        MacosSeatbeltProfileExtensions.new(
          macos_preferences: union_macos_preferences_permission(
            base.macos_preferences,
            permissions.macos_preferences
          ),
          macos_automation: union_macos_automation_permission(
            base.macos_automation,
            permissions.macos_automation
          ),
          macos_launch_services: base.macos_launch_services? || permissions.macos_launch_services?,
          macos_accessibility: base.macos_accessibility? || permissions.macos_accessibility?,
          macos_calendar: base.macos_calendar? || permissions.macos_calendar?,
          macos_reminders: base.macos_reminders? || permissions.macos_reminders?,
          macos_contacts: union_macos_contacts_permission(
            base.macos_contacts,
            permissions.macos_contacts
          )
        )
      end

      def self.intersect_macos_seatbelt_profile_extensions(
        requested : MacosSeatbeltProfileExtensions?,
        granted : MacosSeatbeltProfileExtensions?,
      ) : MacosSeatbeltProfileExtensions?
        if requested && granted
          MacosSeatbeltProfileExtensions.new(
            macos_preferences: requested.macos_preferences <= granted.macos_preferences ? requested.macos_preferences : granted.macos_preferences,
            macos_automation: intersect_macos_automation_permission(
              requested.macos_automation,
              granted.macos_automation
            ),
            macos_launch_services: requested.macos_launch_services? && granted.macos_launch_services?,
            macos_accessibility: requested.macos_accessibility? && granted.macos_accessibility?,
            macos_calendar: requested.macos_calendar? && granted.macos_calendar?,
            macos_reminders: requested.macos_reminders? && granted.macos_reminders?,
            macos_contacts: requested.macos_contacts <= granted.macos_contacts ? requested.macos_contacts : granted.macos_contacts
          )
        end
      end

      def self.union_macos_preferences_permission(
        base : MacosPreferencesPermission,
        requested : MacosPreferencesPermission,
      ) : MacosPreferencesPermission
        base < requested ? requested : base
      end

      def self.union_macos_contacts_permission(
        base : MacosContactsPermission,
        requested : MacosContactsPermission,
      ) : MacosContactsPermission
        base < requested ? requested : base
      end

      def self.union_macos_automation_permission(
        base : MacosAutomationPermission,
        requested : MacosAutomationPermission,
      ) : MacosAutomationPermission
        return MacosAutomationPermission.all if base.all? || requested.all?
        return requested if base.none?
        return base if requested.none?
        MacosAutomationPermission.bundle_ids(base.bundle_ids + requested.bundle_ids)
      end

      def self.intersect_macos_automation_permission(
        requested : MacosAutomationPermission,
        granted : MacosAutomationPermission,
      ) : MacosAutomationPermission
        return MacosAutomationPermission.none if requested.none? || granted.none?
        return granted if requested.all?
        return requested if granted.all?

        intersection = requested.bundle_ids.select { |bundle_id| granted.bundle_ids.includes?(bundle_id) }
        MacosAutomationPermission.bundle_ids(intersection)
      end
    end
  end
end
