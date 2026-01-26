#include "Config.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{
constexpr auto SECTION_NAME        = "Generic.HashAnalyzer";
constexpr auto KEY_VT_API_KEY      = "VirusTotal.Key";
constexpr auto KEY_DEFAULT_SERVICE = "DefaultService";

Config config;

Config& GetPluginConfig()
{
    return config;
}

void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect               = ini->GetSection(SECTION_NAME);
        this->VirusTotal.ApiKey = sect.GetValue(KEY_VT_API_KEY).ToStringView();
        this->DefaultService    = sect.GetValue(KEY_DEFAULT_SERVICE).ToStringView();
    }
    this->Loaded = true;
}

void Config::Update(AppCUI::Utils::IniSection sect)
{
    sect.UpdateValue(KEY_VT_API_KEY, "", true);
    sect.UpdateValue(KEY_DEFAULT_SERVICE, "virustotal", true);
}

void Config::Save()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini) {
        auto sect                 = ini->GetSection(SECTION_NAME);
        sect[KEY_VT_API_KEY]      = this->VirusTotal.ApiKey;
        sect[KEY_DEFAULT_SERVICE] = this->DefaultService;
        ini->Save(AppCUI::Application::GetAppSettingsFile());
    }
}
} // namespace GView::GenericPlugins::HashAnalyzer
