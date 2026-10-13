#pragma once

#include "GView.hpp"

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Key bindings registry: the single source of truth for every rebindable key in GView.
//  - bindings are identified by (section, caption); sections are "GView", "View.<Viewer>", "Type.<Plugin>",
//    "Generic.<Plugin>"
//  - only user overrides are persisted (ini section "[Keys.<section>]", value "<caption> = <key>" or "None"), the
//    defaults always come from the code (KeyboardControl::DefaultKey) or from the plugin declared "Command.*" values
//  - the registry never keeps pointers to KeyboardControl objects (they may live inside plugin libraries); keys are
//    pushed into the objects through short-lived ApplyPass objects
// This file has no UI dependencies (unit tested in tests_keybindings.cpp).
namespace GView::App::Keys
{
using AppCUI::Input::Key;

constexpr std::string_view SECTION_GVIEW         = "GView";
constexpr std::string_view SECTION_VIEW_PREFIX   = "View.";
constexpr std::string_view SECTION_TYPE_PREFIX   = "Type.";
constexpr std::string_view SECTION_GENERIC_PREFIX = "Generic.";
constexpr std::string_view INI_SECTION_PREFIX    = "Keys.";
constexpr std::string_view INI_UNASSIGNED        = "None";
// categories (of a type plugin) whose name starts with this prefix hold panel keys ("Panels", "Panel: Resources", ...)
constexpr std::string_view PANELS_CATEGORY_PREFIX = "Panel";

using CaptionMap  = std::map<std::string, Key, std::less<>>;
using OverrideMap = std::map<std::string, CaptionMap, std::less<>>; // section -> caption -> key (ordered: deterministic)

class Registry
{
    OverrideMap overrides;
    // values written by older GView versions in "[View.*] Key.<caption>"; used only when they differ from the default
    OverrideMap legacy;
    // defaults seen by Resolve (lets Save() decide which legacy values are real overrides)
    mutable OverrideMap knownDefaults;

  public:
    void Load(AppCUI::Utils::IniObject& ini);
    // writes "[Keys.*]" (replacing the previous content) and removes the legacy "Key.*" values
    void Save(AppCUI::Utils::IniObject& ini) const;

    Key Resolve(std::string_view section, std::string_view caption, Key defaultKey) const;
    std::optional<Key> GetOverride(std::string_view section, std::string_view caption) const;
    void SetOverride(std::string_view section, std::string_view caption, Key key);
    void ClearOverride(std::string_view section, std::string_view caption);
    void ClearAllOverrides();
    bool HasOverrides() const;
    inline const OverrideMap& GetOverrides() const
    {
        return overrides;
    }

    static std::string MakeIniSectionName(std::string_view section);
    static bool KeyToText(Key key, AppCUI::Utils::String& text);
    static std::optional<Key> TextToKey(std::string_view text);
};

// Writes the resolved key (override or default) into each registered (non read-only) KeyboardControl
class ApplyPass : public KeyboardControlsInterface
{
    const Registry& registry;
    std::string section;

  public:
    ApplyPass(const Registry& registry, std::string_view section);
    bool RegisterKey(KeyboardControl* key) override;
    bool BeginCategory(std::string_view name) override;
    bool RegisterKeyText(std::string_view keys, std::string_view caption, std::string_view explanation) override;
};

// One entry of the "Keyboard shortcuts" window (owns all its strings)
struct Row
{
    std::string section;     // registry section ("View.Buffer", "Type.PE", ...)
    std::string group;       // display group ("PE plugin", "Buffer viewer", "GView", ...)
    std::string category;    // optional sub group ("Panels", "Navigation & editing", ...)
    std::string caption;     // registry identifier
    std::string explanation; // description
    std::string keyText;     // display-only rows: the textual key description ("0-9", "[ / ]")
    Key key        = Key::None;
    Key defaultKey = Key::None;
    KeyboardControlFlags flags = KeyboardControlFlags::None;
    bool displayOnly           = false;
    int32 conflictWith         = -1; // index (in the same rows vector) of a row using the same key in the same context

    inline bool IsEditable() const
    {
        return (!displayOnly) && ((static_cast<uint8>(flags) & static_cast<uint8>(KeyboardControlFlags::ReadOnly)) == 0);
    }
    inline bool HasFlag(KeyboardControlFlags flag) const
    {
        return (static_cast<uint8>(flags) & static_cast<uint8>(flag)) != 0;
    }
};

// Snapshots registered keys as rows (null-safe: entries with a null caption are ignored)
class Collector : public KeyboardControlsInterface
{
    std::vector<Row>& rows;
    std::string section;
    std::string group;
    std::string category;

  public:
    explicit Collector(std::vector<Row>& rows);
    void SetSection(std::string_view section, std::string_view group);
    // adds a plugin command (from the "Command.*" settings) unless a key with the same caption is already listed
    void AddCommand(std::string_view caption, std::string_view explanation, Key key, Key defaultKey);
    bool RegisterKey(KeyboardControl* key) override;
    bool BeginCategory(std::string_view name) override;
    bool RegisterKeyText(std::string_view keys, std::string_view caption, std::string_view explanation) override;
};

// Recomputes every row key from (pending) overrides
void ResolveRows(std::vector<Row>& rows, const Registry& registry);

// Marks rows whose key is also used by another row that can be active at the same time:
//  - GView and Generic keys are always active
//  - "View.X" keys are active only while viewer X has the focus, "Panel*" keys only while a panel has the focus
//    (keys of two different panel categories are never active together)
//  - "Type.X" keys are active only for files of type X
void ComputeConflicts(std::vector<Row>& rows);
} // namespace GView::App::Keys
