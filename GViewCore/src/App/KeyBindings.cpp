#include "KeyBindings.hpp"

namespace GView::App::Keys
{
using namespace AppCUI::Utils;

namespace
{
    bool StartsWithIgnoreCase(std::string_view text, std::string_view prefix)
    {
        if (text.size() < prefix.size())
            return false;
        for (size_t i = 0; i < prefix.size(); i++)
        {
            auto a = text[i], b = prefix[i];
            if ((a >= 'A') && (a <= 'Z'))
                a |= 0x20;
            if ((b >= 'A') && (b <= 'Z'))
                b |= 0x20;
            if (a != b)
                return false;
        }
        return true;
    }
    bool EqualsIgnoreCase(std::string_view a, std::string_view b)
    {
        return (a.size() == b.size()) && StartsWithIgnoreCase(a, b);
    }
    const Key* Find(const OverrideMap& map, std::string_view section, std::string_view caption)
    {
        const auto s = map.find(section);
        if (s == map.end())
            return nullptr;
        const auto c = s->second.find(caption);
        if (c == s->second.end())
            return nullptr;
        return &c->second;
    }
} // namespace

//====================================================================================== Registry ===
std::string Registry::MakeIniSectionName(std::string_view section)
{
    std::string result;
    result.reserve(INI_SECTION_PREFIX.size() + section.size());
    result.append(INI_SECTION_PREFIX);
    result.append(section);
    return result;
}
bool Registry::KeyToText(Key key, String& text)
{
    if (key == Key::None)
        return text.Set(INI_UNASSIGNED);
    return KeyUtils::ToString(key, text);
}
std::optional<Key> Registry::TextToKey(std::string_view text)
{
    if (EqualsIgnoreCase(text, INI_UNASSIGNED))
        return Key::None;
    const auto key = KeyUtils::FromString(text);
    if (key == Key::None)
        return std::nullopt; // invalid text
    return key;
}
void Registry::Load(IniObject& ini)
{
    overrides.clear();
    legacy.clear();
    for (auto section : ini.GetSections())
    {
        const auto name = section.GetName();
        if (StartsWithIgnoreCase(name, INI_SECTION_PREFIX))
        {
            const auto bindingSection = name.substr(INI_SECTION_PREFIX.size());
            if (bindingSection.empty())
                continue;
            for (auto value : section.GetValues())
            {
                const auto key = TextToKey(value.ToStringView());
                if (!key.has_value())
                {
                    LOG_WARNING("Invalid key value in [%s]: %s (ignored)", std::string(name).c_str(), std::string(value.GetName()).c_str());
                    continue;
                }
                overrides[std::string(bindingSection)][std::string(value.GetName())] = key.value();
            }
        }
        else if (StartsWithIgnoreCase(name, SECTION_VIEW_PREFIX) || EqualsIgnoreCase(name, SECTION_GVIEW))
        {
            // legacy (pre-registry) format: [View.Buffer] Key.ChangeColumnsCount = F6, [GView] Key.ChangeView = F4
            for (auto value : section.GetValues())
            {
                const auto valueName = value.GetName();
                if (!StartsWithIgnoreCase(valueName, "Key."))
                    continue;
                const auto key = value.AsKey();
                if (key.has_value())
                    legacy[EqualsIgnoreCase(name, SECTION_GVIEW) ? std::string(SECTION_GVIEW) : std::string(name)][std::string(valueName.substr(4))] =
                          key.value();
            }
        }
    }
}
void Registry::Save(IniObject& ini) const
{
    // promote the legacy values that differ from a known default (and that were not overwritten)
    OverrideMap result = overrides;
    for (const auto& [section, captions] : legacy)
    {
        for (const auto& [caption, key] : captions)
        {
            const auto def = Find(knownDefaults, section, caption);
            if ((def) && (*def != key) && (!Find(result, section, caption)))
                result[section][caption] = key;
        }
    }

    // remove the previous [Keys.*] sections and the legacy Key.* values
    std::vector<std::string> sectionsToDelete;
    for (auto section : ini.GetSections())
    {
        const auto name = section.GetName();
        if (StartsWithIgnoreCase(name, INI_SECTION_PREFIX))
        {
            sectionsToDelete.emplace_back(name);
        }
        else if (StartsWithIgnoreCase(name, SECTION_VIEW_PREFIX) || EqualsIgnoreCase(name, SECTION_GVIEW))
        {
            std::vector<std::string> valuesToDelete;
            for (auto value : section.GetValues())
                if (StartsWithIgnoreCase(value.GetName(), "Key."))
                    valuesToDelete.emplace_back(value.GetName());
            for (const auto& v : valuesToDelete)
                section.DeleteValue(v);
        }
    }
    for (const auto& s : sectionsToDelete)
        ini.DeleteSection(s);

    LocalString<64> text;
    for (const auto& [section, captions] : result)
    {
        if (captions.empty())
            continue;
        auto iniSection = ini[MakeIniSectionName(section)];
        for (const auto& [caption, key] : captions)
        {
            if (KeyToText(key, text))
                iniSection[caption] = text.ToStringView();
        }
    }
}
Key Registry::Resolve(std::string_view section, std::string_view caption, Key defaultKey) const
{
    knownDefaults[std::string(section)][std::string(caption)] = defaultKey;
    if (const auto o = Find(overrides, section, caption))
        return *o;
    if (const auto l = Find(legacy, section, caption))
        return *l;
    return defaultKey;
}
std::optional<Key> Registry::GetOverride(std::string_view section, std::string_view caption) const
{
    if (const auto o = Find(overrides, section, caption))
        return *o;
    if (const auto l = Find(legacy, section, caption))
    {
        const auto def = Find(knownDefaults, section, caption);
        if ((!def) || (*def != *l))
            return *l;
    }
    return std::nullopt;
}
void Registry::SetOverride(std::string_view section, std::string_view caption, Key key)
{
    overrides[std::string(section)][std::string(caption)] = key;
}
void Registry::ClearOverride(std::string_view section, std::string_view caption)
{
    auto s = overrides.find(section);
    if (s != overrides.end())
    {
        auto c = s->second.find(caption);
        if (c != s->second.end())
            s->second.erase(c);
        if (s->second.empty())
            overrides.erase(s);
    }
    // a legacy value is an override too -> drop it (the default will be used)
    auto l = legacy.find(section);
    if (l != legacy.end())
    {
        auto c = l->second.find(caption);
        if (c != l->second.end())
            l->second.erase(c);
    }
}
void Registry::ClearAllOverrides()
{
    overrides.clear();
    legacy.clear();
}
bool Registry::HasOverrides() const
{
    return !overrides.empty();
}

//====================================================================================== ApplyPass ===
ApplyPass::ApplyPass(const Registry& r, std::string_view s) : registry(r), section(s)
{
}
bool ApplyPass::RegisterKey(KeyboardControl* key)
{
    if ((key == nullptr) || (key->Caption == nullptr))
        return false;
    if (key->HasFlag(KeyboardControlFlags::ReadOnly))
        return true;
    key->Key = registry.Resolve(section, key->Caption, key->DefaultKey);
    return true;
}
bool ApplyPass::BeginCategory(std::string_view)
{
    return true;
}
bool ApplyPass::RegisterKeyText(std::string_view, std::string_view, std::string_view)
{
    return true;
}

//====================================================================================== Collector ===
Collector::Collector(std::vector<Row>& r) : rows(r)
{
}
void Collector::SetSection(std::string_view s, std::string_view g)
{
    section = s;
    group   = g;
    category.clear();
}
void Collector::AddCommand(std::string_view caption, std::string_view explanation, Key key, Key defaultKey)
{
    for (const auto& r : rows)
        if ((r.section == section) && (r.caption == caption) && (!r.displayOnly))
            return; // already registered by the plugin (with a better description)
    Row r;
    r.section     = section;
    r.group       = group;
    r.caption     = caption;
    r.explanation = explanation;
    r.key         = key;
    r.defaultKey  = defaultKey;
    rows.push_back(std::move(r));
}
bool Collector::RegisterKey(KeyboardControl* key)
{
    if ((key == nullptr) || (key->Caption == nullptr))
        return false;
    for (const auto& r : rows)
        if ((r.section == section) && (r.caption == key->Caption) && (!r.displayOnly))
            return true; // same binding registered twice -> keep the first one
    Row r;
    r.section     = section;
    r.group       = group;
    r.category    = category;
    r.caption     = key->Caption;
    r.explanation = key->Explanation ? key->Explanation : "";
    r.key         = key->Key;
    r.defaultKey  = key->DefaultKey;
    r.flags       = key->Flags;
    rows.push_back(std::move(r));
    return true;
}
bool Collector::BeginCategory(std::string_view name)
{
    category = name;
    return true;
}
bool Collector::RegisterKeyText(std::string_view keys, std::string_view caption, std::string_view explanation)
{
    Row r;
    r.section     = section;
    r.group       = group;
    r.category    = category;
    r.caption     = caption;
    r.explanation = explanation;
    r.keyText     = keys;
    r.displayOnly = true;
    r.flags       = KeyboardControlFlags::ReadOnly;
    rows.push_back(std::move(r));
    return true;
}

//====================================================================================== Rows ===
void ResolveRows(std::vector<Row>& rows, const Registry& registry)
{
    for (auto& r : rows)
        if (r.IsEditable())
            r.key = registry.Resolve(r.section, r.caption, r.defaultKey);
}

namespace
{
    enum class ContextKind : uint8
    {
        Global,
        Plugin,
        Panel,
        Viewer
    };
    struct Context
    {
        ContextKind kind;
        std::string_view owner;    // section
        std::string_view category; // for panels: keys of different panel groups are never active together
    };
    Context GetContext(const Row& r)
    {
        const std::string_view section = r.section;
        if (StartsWithIgnoreCase(section, SECTION_VIEW_PREFIX))
            return { ContextKind::Viewer, section, {} };
        if (StartsWithIgnoreCase(section, SECTION_TYPE_PREFIX))
        {
            if (StartsWithIgnoreCase(r.category, PANELS_CATEGORY_PREFIX))
                return { ContextKind::Panel, section, r.category };
            return { ContextKind::Plugin, section, {} };
        }
        return { ContextKind::Global, section, {} };
    }
    bool CanBeActiveTogether(const Context& a, const Context& b)
    {
        if ((a.kind == ContextKind::Global) || (b.kind == ContextKind::Global))
            return true;
        const bool sameOwner = a.owner == b.owner;
        switch (a.kind)
        {
        case ContextKind::Plugin:
            return (b.kind == ContextKind::Viewer) || sameOwner;
        case ContextKind::Panel:
            if (b.kind == ContextKind::Panel)
                return sameOwner && (a.category == b.category);
            return (b.kind == ContextKind::Plugin) && sameOwner;
        case ContextKind::Viewer:
            return (b.kind == ContextKind::Plugin) || ((b.kind == ContextKind::Viewer) && sameOwner);
        default:
            return true;
        }
    }
} // namespace

void ComputeConflicts(std::vector<Row>& rows)
{
    // key -> indexes of the rows that react to that key
    std::map<uint32, std::vector<uint32>> byKey;
    for (uint32 i = 0; i < static_cast<uint32>(rows.size()); i++)
    {
        auto& r        = rows[i];
        r.conflictWith = -1;
        if (r.displayOnly || (r.key == Key::None))
            continue;
        byKey[static_cast<uint32>(r.key)].push_back(i);
        if (r.HasFlag(KeyboardControlFlags::ShiftExtendsSelection))
            byKey[static_cast<uint32>(r.key) | static_cast<uint32>(Key::Shift)].push_back(i);
    }
    for (const auto& [key, indexes] : byKey)
    {
        for (size_t a = 0; a < indexes.size(); a++)
        {
            for (size_t b = 0; b < indexes.size(); b++)
            {
                if ((a == b) || (indexes[a] == indexes[b]))
                    continue;
                auto& ra = rows[indexes[a]];
                if (ra.conflictWith >= 0)
                    break;
                if (CanBeActiveTogether(GetContext(ra), GetContext(rows[indexes[b]])))
                {
                    ra.conflictWith = static_cast<int32>(indexes[b]);
                    break;
                }
            }
        }
    }
}
} // namespace GView::App::Keys
