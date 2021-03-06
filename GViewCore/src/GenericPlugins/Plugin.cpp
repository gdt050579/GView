#include "Internal.hpp"

using namespace GView::Generic;
using namespace GView::Utils;
using namespace GView;

namespace GView::Generic
{

Plugin::Plugin()
{
    this->CommandsCount = 0;
    this->fnRun         = nullptr;
}
bool Plugin::Init(AppCUI::Utils::IniSection section)
{
    // set the name
    auto name = section.GetName();
    CHECK(name.length() > 8, false, "Expected a name after 'Generic.' !");
    this->Name          = name.substr(8);
    this->CommandsCount = 0;
    this->fnRun         = nullptr;
    for (auto val : section)
    {
        auto valueName = val.GetName();
        if (String::StartsWith(valueName, "command.", true))
        {
            auto key = val.AsKey();
            CHECK(key.has_value(), false, "Expecting a key value for: %s", valueName.data());
            CHECK(this->CommandsCount < MAX_PLUGINS_COMMANDS, false, "Too many commands - max allowed is #d", MAX_PLUGINS_COMMANDS);
            this->Commands[this->CommandsCount].Name     = valueName.substr(8); // 8 = sizeof(commands.)
            this->Commands[this->CommandsCount].ShortKey = key.value();
            this->CommandsCount++;
        }
    }

    return true;
}
void Plugin::Run(uint32 commandIndex, Reference<GView::Object> currentObject)
{
    if (!this->fnRun)
    {
        // we need to load the library
        AppCUI::OS::Library lib;
        auto path = AppCUI::OS::GetCurrentApplicationPath();
        path.remove_filename();
        path /= "GenericPlugins";
        path /= "lib";
        path += (std::string_view) this->Name;
        path += ".gpl";
        if (lib.Load(path)==false)
        {
            LocalString<1024> info;
            info.Format("Fail to load library: %s", path.generic_string().c_str());
            AppCUI::Dialogs::MessageBox::ShowError("Error", info);
            return;
        }

        this->fnRun            = lib.GetFunction<decltype(this->fnRun)>("Run");
        if (!this->fnRun)
        {
            LocalString<1024> info;
            info.Format("Unable to find `Run` export in : %s", path.generic_string().c_str());
            AppCUI::Dialogs::MessageBox::ShowError("Error", info);
            return;
        }
    }
    // all good -> is loaded ==> try to run
    if (!this->fnRun(this->Commands[commandIndex].Name, currentObject))
    {
        LocalString<1024> info;
        info.Format("Command `%s` from generic plugin: `%s` failed !", this->Commands[commandIndex].Name.GetText(), this->Name.GetText());
        AppCUI::Dialogs::MessageBox::ShowError("Error", info);
    }
}
void Plugin::UpdateCommandBar(AppCUI::Application::CommandBar& commandBar, uint32 commandID)
{
    for (auto idx = 0U; idx < this->CommandsCount; idx++)
    {
        commandBar.SetCommand(this->Commands[idx].ShortKey, this->Commands[idx].Name, commandID + idx);
    }
}
} // namespace GView::Generic
/*
bool Plugin::LoadPlugin()
{
  AppCUI::OS::Library lib;
  auto path = AppCUI::OS::GetCurrentApplicationPath();
  path.remove_filename();
  path /= "Types";
  path /= "lib";
  path += std::string_view((const char*) this->Name, this->NameLength);
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
  if (this->Patterns.empty())
  {
      if (this->Pattern.Empty() == false)
      {
          matched = this->Pattern.Match(buf);
      }
  }
  else
  {
      for (auto& p : this->Patterns)
      {
          if ((matched = p.Match(buf)) == true)
              break;
      }
  }
  if ((!matched) && ((this->Extension != EXTENSION_EMPTY_HASH) || (!this->Extensions.empty())))
  {
      auto hash = ExtensionToHash(extension);
      if (this->Extensions.empty())
          matched = hash == this->Extension;
      else
          matched = this->Extensions.contains(hash);
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
TypeInterface* Plugin::CreateInstance(Reference<GView::Utils::DataCache> fileCache) const
{
  CHECK(!this->Invalid, nullptr, "Invalid plugin (not loaded properly or no valid exports)");
  CHECK(this->Loaded, nullptr, "Plugin was no loaded. Have you call `Validate` first ?");
  return this->fnCreateInstance(fileCache);
}
*/