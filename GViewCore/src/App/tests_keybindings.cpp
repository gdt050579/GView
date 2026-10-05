#include <catch.hpp>
#include "KeyBindings.hpp"

using namespace GView::App::Keys;
using AppCUI::Input::Key;
using AppCUI::Input::KeyBindingFlags;
using AppCUI::Input::KeyMap;
using AppCUI::Input::ModifierMap;
using AppCUI::Utils::IniObject;
using AppCUI::Utils::KeyUtils;
using AppCUI::Utils::LocalString;

//================================================================================== AppCUI primitives ===
TEST_CASE("ModifierMap identity and Ctrl/Alt swap", "[KeyBindings]")
{
    const auto identity = ModifierMap::Identity();
    REQUIRE(identity.IsIdentity());
    REQUIRE(identity.ToLogical(Key::Ctrl | Key::G) == (Key::Ctrl | Key::G));

    auto swapped = ModifierMap::FromAssignments(Key::Alt, Key::Ctrl);
    REQUIRE(swapped.has_value());
    REQUIRE_FALSE(swapped->IsIdentity());
    // physical Ctrl+G -> logical Alt+G and back
    REQUIRE(swapped->ToLogical(Key::Ctrl | Key::G) == (Key::Alt | Key::G));
    REQUIRE(swapped->ToLogical(Key::Alt | Key::F) == (Key::Ctrl | Key::F));
    REQUIRE(swapped->ToLogical(Key::Ctrl | Key::Alt | Key::Shift | Key::F1) == (Key::Ctrl | Key::Alt | Key::Shift | Key::F1));
    REQUIRE(swapped->ToLogical(Key::Shift | Key::Tab) == (Key::Shift | Key::Tab));
    REQUIRE(swapped->ToLogical(Key::F5) == Key::F5);
    // the map is a bijection: ToPhysical(ToLogical(k)) == k for every modifier combination
    for (uint32 mods = 0; mods < 8; mods++)
    {
        const auto k = static_cast<Key>((mods << KeyUtils::KEY_SHIFT_BITS) | static_cast<uint32>(Key::A));
        REQUIRE(swapped->ToPhysical(swapped->ToLogical(k)) == k);
    }
    REQUIRE(swapped->GetCtrlActsAs() == Key::Alt);
    REQUIRE(swapped->GetAltActsAs() == Key::Ctrl);
}

TEST_CASE("ModifierMap rejects non bijective profiles", "[KeyBindings]")
{
    REQUIRE_FALSE(ModifierMap::FromAssignments(Key::Ctrl, Key::Ctrl).has_value());
    REQUIRE_FALSE(ModifierMap::FromAssignments(Key::Ctrl | Key::Shift, Key::Alt).has_value());
    REQUIRE_FALSE(ModifierMap::FromAssignments(Key::None, Key::Alt).has_value());
    REQUIRE_FALSE(ModifierMap::FromAssignments(Key::Ctrl | Key::A, Key::Alt).has_value()); // not only modifiers
    auto standard = ModifierMap::FromAssignments(Key::Ctrl, Key::Alt);
    REQUIRE(standard.has_value());
    REQUIRE(standard->IsIdentity());
}

TEST_CASE("KeyMap resolves exact keys, Shift selection and ignores unassigned keys", "[KeyBindings]")
{
    AppCUI::Input::KeyBinding down = { Key::Down, "MoveDown", "", 10, KeyBindingFlags::ShiftExtendsSelection };
    AppCUI::Input::KeyBinding scroll = { Key::Ctrl | Key::Down, "ScrollDown", "", 11 };
    AppCUI::Input::KeyBinding unassigned = { Key::None, "Nothing", "", 12 };
    AppCUI::Input::KeyBinding duplicate = { Key::Down, "Duplicate", "", 13 };
    const std::array<AppCUI::Input::KeyBinding*, 4> bindings = { &down, &scroll, &unassigned, &duplicate };

    KeyMap map;
    REQUIRE(map.Resolve(Key::Down).commandId == KeyMap::NO_COMMAND); // empty map
    map.Build(bindings);

    auto r = map.Resolve(Key::Down);
    REQUIRE(r.commandId == 10); // first binding wins
    REQUIRE_FALSE(r.extendSelection);

    r = map.Resolve(Key::Shift | Key::Down);
    REQUIRE(r.commandId == 10);
    REQUIRE(r.extendSelection);

    REQUIRE(map.Resolve(Key::Ctrl | Key::Down).commandId == 11);
    // Shift + a key without ShiftExtendsSelection is not matched
    REQUIRE(map.Resolve(Key::Ctrl | Key::Shift | Key::Down).commandId == KeyMap::NO_COMMAND);
    // Key::None (punctuation on terminals) never matches an unassigned binding
    REQUIRE(map.Resolve(Key::None).commandId == KeyMap::NO_COMMAND);
    REQUIRE_FALSE(unassigned.Matches(Key::None));

    // many bindings -> the table grows
    std::vector<AppCUI::Input::KeyBinding> many;
    many.reserve(40);
    for (uint32 i = 0; i < 26; i++)
        many.emplace_back(static_cast<Key>(static_cast<uint32>(Key::A) + i) | Key::Alt, "x", "", 100 + i);
    std::vector<AppCUI::Input::KeyBinding*> ptrs;
    for (auto& b : many)
        ptrs.push_back(&b);
    map.Build(ptrs);
    for (uint32 i = 0; i < 26; i++)
        REQUIRE(map.Resolve(static_cast<Key>(static_cast<uint32>(Key::A) + i) | Key::Alt).commandId == 100 + i);
}

TEST_CASE("KeyUtils key names round-trip (Right arrow, case-insensitive, legacy 'Righ')", "[KeyBindings]")
{
    LocalString<64> text;
    REQUIRE(KeyUtils::ToString(Key::Ctrl | Key::Right, text));
    REQUIRE(std::string_view(text.GetText()) == "Ctrl+Right");
    REQUIRE(KeyUtils::FromString("Ctrl+Right") == (Key::Ctrl | Key::Right));
    REQUIRE(KeyUtils::FromString("ctrl+right") == (Key::Ctrl | Key::Right));
    REQUIRE(KeyUtils::FromString("Shift+Righ") == (Key::Shift | Key::Right));
    REQUIRE(KeyUtils::FromString("alt+shift+f7") == (Key::Alt | Key::Shift | Key::F7));
    REQUIRE(KeyUtils::FromString("Bogus") == Key::None);

    const auto swapped = ModifierMap::FromAssignments(Key::Alt, Key::Ctrl).value();
    REQUIRE(KeyUtils::ToDisplayString(Key::Alt | Key::G, swapped, text));
    REQUIRE(std::string_view(text.GetText()) == "Ctrl+G"); // logical Alt+G is pressed as Ctrl+G
}

//================================================================================== Registry ===
TEST_CASE("Registry resolves overrides, unassigned keys and legacy values", "[KeyBindings]")
{
    IniObject ini;
    REQUIRE(ini.CreateFromString(
          "[Keys.View.Buffer]\n"
          "ChangeColumnsCount = Ctrl+F6\n"
          "GoToEntryPoint = None\n"
          "Broken = NotAKey\n"
          "[View.Buffer]\n"
          "Key.ChangeAddressMode = F3\n"
          "Key.FindNext = Ctrl+F8\n"
          "[GView]\n"
          "Key.ChangeView = F12\n"));
    Registry registry;
    registry.Load(ini);

    REQUIRE(registry.Resolve("View.Buffer", "ChangeColumnsCount", Key::F6) == (Key::Ctrl | Key::F6));
    REQUIRE(registry.Resolve("View.Buffer", "GoToEntryPoint", Key::F7) == Key::None);
    REQUIRE(registry.Resolve("View.Buffer", "Broken", Key::F1) == Key::F1); // invalid values are ignored
    REQUIRE(registry.Resolve("View.Buffer", "Unknown", Key::F2) == Key::F2);
    // legacy values: equal to the default -> not an override, different -> override
    REQUIRE(registry.Resolve("View.Buffer", "ChangeAddressMode", Key::F3) == Key::F3);
    REQUIRE_FALSE(registry.GetOverride("View.Buffer", "ChangeAddressMode").has_value());
    REQUIRE(registry.Resolve("View.Buffer", "FindNext", Key::Ctrl | Key::F7) == (Key::Ctrl | Key::F8));
    REQUIRE(registry.Resolve("GView", "ChangeView", Key::F4) == Key::F12);

    registry.ClearOverride("View.Buffer", "ChangeColumnsCount");
    REQUIRE(registry.Resolve("View.Buffer", "ChangeColumnsCount", Key::F6) == Key::F6);
}

TEST_CASE("Registry save writes only overrides and drops the legacy values", "[KeyBindings]")
{
    IniObject ini;
    REQUIRE(ini.CreateFromString(
          "[View.Buffer]\n"
          "Key.FindNext = Ctrl+F8\n"
          "Key.ChangeAddressMode = F3\n"
          "Config.Something = 1\n"
          "[Keys.Type.PE]\n"
          "Old = F1\n"));
    Registry registry;
    registry.Load(ini);
    // the defaults are known after the keys were resolved once (as GView does at startup)
    registry.Resolve("View.Buffer", "FindNext", Key::Ctrl | Key::F7);
    registry.Resolve("View.Buffer", "ChangeAddressMode", Key::F3);
    registry.ClearOverride("Type.PE", "Old");
    registry.SetOverride("Type.PE", "DigitalSignature", Key::Alt | Key::F9);
    registry.SetOverride("View.Lexical", "FoldAll", Key::None);
    registry.Save(ini);

    REQUIRE_FALSE(ini.GetSection("View.Buffer").HasValue("Key.FindNext"));
    REQUIRE_FALSE(ini.GetSection("View.Buffer").HasValue("Key.ChangeAddressMode"));
    REQUIRE(ini.GetSection("View.Buffer").HasValue("Config.Something"));
    REQUIRE(ini.GetSection("Keys.View.Buffer").GetValue("FindNext").AsKey() == (Key::Ctrl | Key::F8)); // promoted legacy value
    REQUIRE_FALSE(ini.GetSection("Keys.View.Buffer").HasValue("ChangeAddressMode"));                  // equal to the default
    REQUIRE(ini.GetSection("Keys.Type.PE").GetValue("DigitalSignature").AsKey() == (Key::Alt | Key::F9));
    REQUIRE_FALSE(ini.GetSection("Keys.Type.PE").HasValue("Old"));
    REQUIRE(ini.GetSection("Keys.View.Lexical").GetValue("FoldAll").ToStringView() == "None");

    // round trip
    Registry reloaded;
    reloaded.Load(ini);
    REQUIRE(reloaded.Resolve("View.Lexical", "FoldAll", Key::F9) == Key::None);
    REQUIRE(reloaded.Resolve("Type.PE", "DigitalSignature", Key::Alt | Key::F8) == (Key::Alt | Key::F9));
}

TEST_CASE("Saving an empty registry removes every key customization (configuration reset)", "[KeyBindings]")
{
    IniObject ini;
    REQUIRE(ini.CreateFromString(
          "[GView]\n"
          "CacheSize = 10\n"
          "Key.ChangeView = F12\n"
          "[View.Buffer]\n"
          "Key.FindNext = Ctrl+F8\n"
          "Config.Something = 1\n"
          "[Keys.View.Buffer]\n"
          "ChangeColumnsCount = Ctrl+F6\n"
          "[Keys.Type.PE]\n"
          "DigitalSignature = Alt+F9\n"
          "[Type.PE]\n"
          "Command.DigitalSignature = Alt+F8\n"));
    Registry{}.Save(ini);

    REQUIRE_FALSE(ini.HasSection("Keys.View.Buffer"));
    REQUIRE_FALSE(ini.HasSection("Keys.Type.PE"));
    REQUIRE_FALSE(ini.GetSection("GView").HasValue("Key.ChangeView"));
    REQUIRE_FALSE(ini.GetSection("View.Buffer").HasValue("Key.FindNext"));
    // everything else is kept (plugin declared commands are defaults, not customizations)
    REQUIRE(ini.GetSection("GView").HasValue("CacheSize"));
    REQUIRE(ini.GetSection("View.Buffer").HasValue("Config.Something"));
    REQUIRE(ini.GetSection("Type.PE").GetValue("Command.DigitalSignature").AsKey() == (Key::Alt | Key::F8));

    Registry reloaded;
    reloaded.Load(ini);
    REQUIRE_FALSE(reloaded.HasOverrides());
    REQUIRE(reloaded.Resolve("GView", "ChangeView", Key::F4) == Key::F4);
}

//================================================================================== Collector / ApplyPass ===
TEST_CASE("ApplyPass writes the resolved keys and keeps read-only keys", "[KeyBindings]")
{
    Registry registry;
    registry.SetOverride("View.Test", "Editable", Key::Ctrl | Key::E);
    registry.SetOverride("View.Test", "Fixed", Key::Ctrl | Key::X);
    GView::KeyboardControl editable = { Key::E, "Editable", "", 1 };
    GView::KeyboardControl fixed    = { Key::F, "Fixed", "", 2, KeyBindingFlags::ReadOnly };
    ApplyPass pass(registry, "View.Test");
    REQUIRE(pass.RegisterKey(&editable));
    REQUIRE(pass.RegisterKey(&fixed));
    REQUIRE_FALSE(pass.RegisterKey(nullptr));
    REQUIRE(editable.Key == (Key::Ctrl | Key::E));
    REQUIRE(editable.DefaultKey == Key::E);
    REQUIRE(editable.IsModified());
    REQUIRE(fixed.Key == Key::F);

    registry.ClearOverride("View.Test", "Editable");
    ApplyPass reset(registry, "View.Test");
    reset.RegisterKey(&editable);
    REQUIRE(editable.Key == Key::E);
}

TEST_CASE("Collector builds rows (null safe, categories, plugin commands)", "[KeyBindings]")
{
    std::vector<Row> rows;
    Collector collector(rows);
    collector.SetSection("Type.PE", "PE plugin");
    GView::KeyboardControl cmd = { Key::Alt | Key::F8, "DigitalSignature", "Validate the signature", 0 };
    GView::KeyboardControl nullCaption = { Key::F1, nullptr, nullptr, 0 };
    REQUIRE(collector.RegisterKey(&cmd));
    REQUIRE_FALSE(collector.RegisterKey(&nullCaption));
    REQUIRE_FALSE(collector.RegisterKey(nullptr));
    collector.AddCommand("DigitalSignature", "Plugin command", Key::Alt | Key::F8, Key::Alt | Key::F8); // already listed
    collector.AddCommand("AreaHighlighter", "Plugin command", Key::Alt | Key::F9, Key::Alt | Key::F9);
    collector.BeginCategory("Panels");
    collector.RegisterKeyText("Enter", "PanelGoTo", "Go to");

    REQUIRE(rows.size() == 3);
    REQUIRE(rows[0].caption == "DigitalSignature");
    REQUIRE(rows[0].explanation == "Validate the signature");
    REQUIRE(rows[1].caption == "AreaHighlighter");
    REQUIRE(rows[2].displayOnly);
    REQUIRE(rows[2].category == "Panels");
    REQUIRE_FALSE(rows[2].IsEditable());
}

//================================================================================== conflicts ===
namespace
{
Row MakeRow(std::string section, std::string category, std::string caption, Key key, KeyBindingFlags flags = KeyBindingFlags::None)
{
    Row r;
    r.section  = std::move(section);
    r.category = std::move(category);
    r.caption  = std::move(caption);
    r.key      = key;
    r.flags    = flags;
    return r;
}
} // namespace

TEST_CASE("Conflicts take the context of the keys into account", "[KeyBindings]")
{
    std::vector<Row> rows = {
        MakeRow("GView", "", "FindDialog", Key::Ctrl | Key::F),                                    // 0 global
        MakeRow("View.Buffer", "", "Something", Key::Ctrl | Key::F),                               // 1 conflicts with 0
        MakeRow("View.Buffer", "", "ChangeSelection", Key::F9),                                    // 2
        MakeRow("Type.PE", "Panels", "PanelSelect", Key::F9),                                      // 3 panel vs viewer: no conflict
        MakeRow("Type.PE", "Panels", "PanelChangeBase", Key::F2),                                  // 4
        MakeRow("Type.PE", "Panel: Resources", "PanelSaveResource", Key::F2),                      // 5 other panel: no conflict
        MakeRow("View.Text", "", "WrapMethod", Key::F9),                                           // 6 other viewer: no conflict with 2
        MakeRow("View.Buffer", "Navigation & editing", "MoveDown", Key::Down, KeyBindingFlags::ShiftExtendsSelection), // 7
        MakeRow("View.Buffer", "", "Other", Key::Shift | Key::Down),                               // 8 conflicts with 7 (Shift)
        MakeRow("Type.ELF", "", "ElfCommand", Key::Alt | Key::F8),                                 // 9
        MakeRow("Type.PE", "", "DigitalSignature", Key::Alt | Key::F8),                            // 10 other plugin: no conflict
        MakeRow("View.Buffer", "", "Unassigned1", Key::None),                                      // 11
        MakeRow("View.Buffer", "", "Unassigned2", Key::None),                                      // 12 unassigned never conflicts
    };
    ComputeConflicts(rows);
    REQUIRE(rows[0].conflictWith == 1);
    REQUIRE(rows[1].conflictWith == 0);
    REQUIRE(rows[2].conflictWith == -1);
    REQUIRE(rows[3].conflictWith == -1);
    REQUIRE(rows[4].conflictWith == -1);
    REQUIRE(rows[5].conflictWith == -1);
    REQUIRE(rows[6].conflictWith == -1);
    REQUIRE(rows[7].conflictWith == 8);
    REQUIRE(rows[8].conflictWith == 7);
    REQUIRE(rows[9].conflictWith == -1);
    REQUIRE(rows[10].conflictWith == -1);
    REQUIRE(rows[11].conflictWith == -1);
    REQUIRE(rows[12].conflictWith == -1);
}
