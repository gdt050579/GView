#include "GView.hpp"

#include "Hashing.hpp"
#include "OnlineAnalyticsUI.hpp"


namespace GView::GenericPlugins::OnlineAnalytics
{
constexpr std::string_view CMD_ONLINE_ANALYTICS = "OnlineAnalytics";

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command != CMD_ONLINE_ANALYTICS) {
        return false;
    }

    if (object->GetData().GetSize() == 0) {
        Dialogs::MessageBox::ShowError("Error!", "Must open a file before running analytics");
        return false;
    }

    String hash = hashSha256(object);

    if (hash.Len() == 0) {
        Dialogs::MessageBox::ShowError("Error!", "There was an error when computing the hash of the file");
        return false;
    }

    Dialogs::MessageBox::ShowNotification("Hash", hash);

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.OnlineAnalytics"] = Input::Key::F11;
}
}

}; // namespace GView::GenericPlugins::OnlineAnalytics