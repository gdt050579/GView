#include <iostream>
#include <curl/curl.h>
#include <format>
#include "GView.hpp"

#include "utils/Hashing.hpp"
#include "utils/Report.hpp"
#include "providers/VirusTotal.hpp"
#include "ui/OnlineAnalyticsProvidersUI.hpp"
#include "ui/OnlineAnalyticsResultsUI.hpp"

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
        return true;
    }

    UI::OnlineAnalyticsProvidersUI providersUi(object);
    CHECK(providersUi.Init() == true, false, "Could not initialise OnlineAnalytics UI");

    if (providersUi.Show() != AppCUI::Dialogs::Result::Ok || object->GetData().GetSize() == 0) {
        return true;
    }

    Reference<Providers::IProvider> provider = providersUi.GetProvider();
    CHECK(provider != NULL, false, "There was an error when selecting the provider: Provider is NULL");

    Reference<std::array<uint8, 32>> hash = Utils::HashSHA256(object);
    CHECK(hash != NULL, false, "There was an error when computing the hash of the file");

    Reference<Utils::Report> report = provider->GetReport(hash);

    if (report == NULL) {
        if (!provider->GetIsUploadSupported()) {
            Dialogs::MessageBox::ShowError("Report retrieval", "The report retrieval failed. Possible reasons: Network failure, file was not previously analyzed or report was not found");
            return true;
        }

        if (Dialogs::MessageBox::ShowOkCancel(
                  "Report retrieval failed",
                  "The report retrieval failed. The file might have not been analysed before. Would you like to upload the file the provider?") ==
            AppCUI::Dialogs::Result::Cancel) {
            return true;
        }

        if (!provider->UploadFile(object)) {
            Dialogs::MessageBox::ShowError(
                  "File upload failed",
                  "An error occured while uploading the file to the given provider. Possible reasons: Network failure or report was not found");
            return true;
        }

        report = provider->GetReport(hash);

        if (report == NULL) {
            Dialogs::MessageBox::ShowError("Report retrieval", "The report retrieval failed. Possible reasons: Network failure or report was not found");
            return true;
        }
    }

    UI::OnlineAnalyticsResultsUI resultsUi(report);
    resultsUi.Init();
    resultsUi.Show();

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.OnlineAnalytics"] = Input::Key::F11;
}
}

}; // namespace GView::GenericPlugins::OnlineAnalytics