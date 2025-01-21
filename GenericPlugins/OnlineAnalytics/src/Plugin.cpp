#include "GView.hpp"
#include <curl/curl.h>
#include <iostream>

#include "utils/Hashing.hpp"
#include "ui/OnlineAnalyticsInitialUI.hpp"
#include "ui/OnlineAnalyticsResultsUI.hpp"

namespace GView::GenericPlugins::OnlineAnalytics
{
constexpr std::string_view CMD_ONLINE_ANALYTICS = "OnlineAnalytics";

using namespace GView::GenericPlugins::OnlineAnalytics::UI;
using namespace GView::GenericPlugins::OnlineAnalytics::Utils;

extern "C" {

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command != CMD_ONLINE_ANALYTICS) {
        return false;
    }

    OnlineAnalyticsInitialUI initialUi(object);

    if (initialUi.Show() != AppCUI::Dialogs::Result::Ok || object->GetData().GetSize() == 0) {
        return true;
    }

    String hash = hashSha256(object);

    CHECK(hash.Len() != 0, false, "There was an error when computing the hash of the file");

    Dialogs::MessageBox::ShowNotification("Hash", hash);

    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    struct curl_slist* headers = NULL;

    curl = curl_easy_init();
    if (curl) {
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, "https://api64.ipify.org/");
        curl_easy_setopt(curl, CURLOPT_HEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        std::cout << readBuffer << std::endl;
    }

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.OnlineAnalytics"] = Input::Key::F11;
}
}

}; // namespace GView::GenericPlugins::OnlineAnalytics