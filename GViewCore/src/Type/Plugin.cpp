#include "Internal.hpp"

using namespace GView::Type;
using namespace GView::Utils;
using namespace GView;

constexpr uint64 EXTENSION_EMPTY_HASH = 0xcbf29ce484222325ULL;

uint64 ExtensionToHash(std::string_view ext)
{
    // use FNV algorithm ==> https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    if (ext.empty())
        return 0;
    auto* s = (const uint8*) ext.data();
    auto* e = s + ext.size();
    if ((*s) == '.')
        s++;
    uint64 hash = EXTENSION_EMPTY_HASH;
    while (s < e)
    {
        uint8 c = *s;
        if ((c >= 'A') && (c <= 'Z'))
            c |= 0x20;

        hash = hash ^ c;
        hash = hash * 0x00000100000001B3ULL;
        s++;
    }
    return hash;
}

Plugin::Plugin()
{
    this->extension  = EXTENSION_EMPTY_HASH;
    this->Loaded     = false;
    this->Invalid    = false;
    this->priority   = 0;
    // functions
    this->fnValidate       = nullptr;
    this->fnCreateInstance = nullptr;
    this->fnPopulateWindow = nullptr;
}
void Plugin::Init()
{
    // default initialization
    this->fnValidate       = DefaultTypePlugin::Validate;
    this->fnCreateInstance = DefaultTypePlugin::CreateInstance;
    this->fnPopulateWindow = DefaultTypePlugin::PopulateWindow;
    this->Loaded           = true;
    this->Invalid          = false;
}
bool Plugin::Init(AppCUI::Utils::IniSection section)
{
    // set the name
    auto pluginName = section.GetName();
    CHECK(pluginName.length() > 5, false, "Expected a name after 'type.' !");
    name.Set(pluginName.substr(5));

    // set the description
    description.Set(section.GetValue("Description").ToStringView());

    // priority
    this->priority = std::max<>(section.GetValue("Priority").ToUInt32(0xFFFF), 0xFFFFU);

    // patterns
    auto MatchOffset  = section.GetValue("MatchOffset").ToUInt32(0);
    auto PatternValue = section.GetValue("Pattern");
    if (PatternValue.HasValue())
    {
        if (PatternValue.IsArray())
        {
            auto count = PatternValue.GetArrayCount();
            for (uint32 index = 0; index < count; index++)
            {
                SimplePattern sp;
                CHECK(sp.Init(PatternValue[index].ToStringView(), MatchOffset), false, "Invalid patern !");
                this->patterns.push_back(sp);
            }
        }
        else
        {
            CHECK(this->pattern.Init(PatternValue.ToStringView(), MatchOffset), false, "Invalid pattern !");
        }
    }

    // extensions
    auto ExtensionValue = section.GetValue("Extension");
    if (ExtensionValue.HasValue())
    {
        if (ExtensionValue.IsArray())
        {
            auto count = ExtensionValue.GetArrayCount();
            for (uint32 index = 0; index < count; index++)
            {
                this->extensions.insert(ExtensionToHash(ExtensionValue[index].ToStringView()));
            }
            this->extension = EXTENSION_EMPTY_HASH;
        }
        else
        {
            this->extension = ExtensionToHash(ExtensionValue.ToStringView());
        }
    }
    else
    {
        this->extension = EXTENSION_EMPTY_HASH;
    }

    // commands
    for (auto item: section)
    {
        auto entryName = item.GetName();
        if (String::StartsWith(entryName, "command.",true))
        {
            auto key = item.AsKey();
            if ((key.has_value()) && (entryName.size() > 8 /* size of Command. */))
            {
                // we have a valid command and key
                if (this->commands.size() == 0)
                    this->commands.reserve(4);
                auto& cmd = this->commands.emplace_back();
                cmd.key   = key.value();
                cmd.name  = entryName.substr(8);
            }
        }
    }
        

    this->Loaded  = false;
    this->Invalid = false;

    return true;
}
bool Plugin::LoadPlugin()
{
    AppCUI::OS::Library lib;
    auto path = AppCUI::OS::GetCurrentApplicationPath();
    path.remove_filename();
    path /= "Types";
    path /= "lib";
    path += this->GetName();
    path += ".tpl";
    CHECK(lib.Load(path), false, "Unable to load: %s", path.generic_string().c_str());

    this->fnValidate       = lib.GetFunction<decltype(this->fnValidate)>("Validate");
    this->fnCreateInstance = lib.GetFunction<decltype(this->fnCreateInstance)>("CreateInstance");
    this->fnPopulateWindow = lib.GetFunction<decltype(this->fnPopulateWindow)>("PopulateWindow");

    CHECK(fnValidate, false, "Missing 'Validate' export !");
    CHECK(fnCreateInstance, false, "Missing 'CreateInstance' export !");
    CHECK(fnPopulateWindow, false, "Missing 'PopulateWindow' export !");

    return true;
}
bool Plugin::Validate(BufferView buf, std::string_view extension)
{
    if (this->Invalid)
        return false; // a load in memory attempt was tryed and failed
    bool matched = false;
    // check if matches any of the existing patterns
    if (this->patterns.empty())
    {
        if (this->pattern.Empty() == false)
        {
            matched = this->pattern.Match(buf);
        }
    }
    else
    {
        for (auto& p : this->patterns)
        {
            if ((matched = p.Match(buf)) == true)
                break;
        }
    }
    if ((!matched) && ((this->extension != EXTENSION_EMPTY_HASH) || (!this->extensions.empty())))
    {
        auto hash = ExtensionToHash(extension);
        if (this->extensions.empty())
            matched = hash == this->extension;
        else
            matched = this->extensions.contains(hash);
    }
    // if initial prefilter was not matched --> exit
    if (!matched)
        return false;
    if (!this->Loaded)
    {
        this->Invalid = !LoadPlugin();
        this->Loaded  = !this->Invalid;
        if (this->Invalid)
            return false; // something went wrong when loading he plugin
    }
    // all good -> code is loaded
    return fnValidate(buf, extension);
}
bool Plugin::PopulateWindow(Reference<GView::View::WindowInterface> win) const
{
    CHECK(!this->Invalid, false, "Invalid plugin (not loaded properly or no valid exports)");
    CHECK(this->Loaded, false, "Plugin was no loaded. Have you call `Validate` first ?");
    return this->fnPopulateWindow(win);
}
TypeInterface* Plugin::CreateInstance() const
{
    CHECK(!this->Invalid, nullptr, "Invalid plugin (not loaded properly or no valid exports)");
    CHECK(this->Loaded, nullptr, "Plugin was no loaded. Have you call `Validate` first ?");
    return this->fnCreateInstance();
}
