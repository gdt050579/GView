#include "FileDownloader.hpp"
#undef MessageBox

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;
using namespace GView::GenericPlugins::FileDownloader;

constexpr int CMD_BUTTON_CLOSE    = 1;
constexpr int CMD_BUTTON_DOWNLOAD = 2;

size_t writeToFile(void* ptr, size_t size, size_t nmemb, void* stream)
{
    OS::File* out          = static_cast<OS::File*>(stream);
    const size_t totalSize = size * nmemb;
    if (!out->Write(static_cast<const char*>(ptr), (uint32) totalSize))
        return 0; // error writing to file
    return totalSize;
}

bool sendHttpRequestAndDownload(const HttpRequest& request, const std::filesystem::path& outputFile, std::string& errorFound)
{
    errorFound.clear();
    CURL* curl = curl_easy_init();
    if (!curl) {
        errorFound = "Failed to initialize CURL";
        return false;
    }

    std::string fullUrl = request.getUrl();
    if (request.hasParams()) {
        fullUrl += "?" + request.getParams();
    }

    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    const std::string& method = request.getMethod();
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (request.hasBody()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.getBody().c_str());
        }
    } else if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    }

    struct curl_slist* curlHeaders = request.generateCurlHeaders();
    if (curlHeaders) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curlHeaders);
    }

    OS::File outFile;
    if (!outFile.Create(outputFile, true) || !outFile.OpenWrite(outputFile)) {
        LocalString<256> localBuffer;
        localBuffer.SetFormat("Failed to create and open output file: %s", outputFile.c_str());
        errorFound = localBuffer.GetText();
        if (curlHeaders)
            curl_slist_free_all(curlHeaders);
        curl_easy_cleanup(curl);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToFile);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outFile);

    const CURLcode res = curl_easy_perform(curl);
    outFile.Close();

    long responseCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);

    if (curlHeaders)
        curl_slist_free_all(curlHeaders);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        errorFound = "CURL error: " + std::string(curl_easy_strerror(res));
        return false;
    }

    if (responseCode >= 200 && responseCode < 300) {
        return true;
    } else {
        errorFound = "HTTP error: " + std::to_string(responseCode);
        return false;
    }
}

class FileDownloaderWindow : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<TextField> urlField, paramsField, methodField, fileName;
    Reference<TextArea> bodyField, headersField;
    bool isInitLibCurl;
    Reference<Window> parent;

  public:
    FileDownloaderWindow(Reference<Window> parent)
        : Window("File downloader", "d:c,w:70,h:23", WindowFlags::Sizeable | WindowFlags::Maximized), isInitLibCurl(false), parent(parent)
    {
        Factory::Label::Create(this, "URL", "l:1,t:1,w:8,h:1");
        urlField = Factory::TextField::Create(this, "www.example.gview.com", "l:9,t:1,r:1");

        Factory::Label::Create(this, "Method", "l:1,t:3,w:8,h:1");
        methodField = Factory::TextField::Create(this, "GET", "l:9,t:3,r:1");

        Factory::Label::Create(this, "Params", "l:1,t:5,w:8,h:1");
        paramsField = Factory::TextField::Create(this, "WIP", "l:9,t:5,r:1");

        Factory::Label::Create(this, "Body", "l:1,t:7,w:8,h:1");
        bodyField = Factory::TextArea::Create(this, "WIP", "l:9,t:7,r:1,h:4");

        Factory::Label::Create(this, "Headers", "l:1,t:12,w:8,h:1");
        headersField = Factory::TextArea::Create(this, "WIP", "l:9,t:12,r:1,h:4");

        Factory::Label::Create(this, "FileName", "l:1,t:17,w:8,h:1");
        fileName = Factory::TextField::Create(this, "output.data", "l:9,t:17,r:1");

        Factory::Button::Create(this, "&Download", "l:15%,b:0,w:20", CMD_BUTTON_DOWNLOAD)->Handlers()->OnButtonPressed = this;
        Factory::Button::Create(this, "&Close", "l:55%,b:0,w:20", CMD_BUTTON_CLOSE)->Handlers()->OnButtonPressed       = this;
    }

    void ValidateAndDownload()
    {
        if (urlField->GetText().IsEmpty()) {
            Dialogs::MessageBox::ShowError("Error", "URL cannot be empty");
            return;
        }
        if (methodField->GetText().IsEmpty()) {
            Dialogs::MessageBox::ShowError("Error", "Method cannot be empty");
            return;
        }
        if (fileName->GetText().IsEmpty()) {
            Dialogs::MessageBox::ShowError("Error", "File name cannot be empty");
            return;
        }

        if (!isInitLibCurl) {
            if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
                Dialogs::MessageBox::ShowError("Error", "Failed to initialize CURL");
                return;
            }
            isInitLibCurl = true;
        }

        HttpRequest request;
        request.setUrl(urlField->GetText()).setMethod(methodField->GetText());

        constexpr char16 currentLoc = '.';
        std::filesystem::path path  = std::u16string_view(&currentLoc, 1);
        path /= fileName->GetText();

        std::string errorFound;
        if (!sendHttpRequestAndDownload(request, path, errorFound)) {
            Dialogs::MessageBox::ShowError("Error", errorFound);
            return;
        } else {
            GView::App::OpenFile(path, App::OpenMethod::BestMatch, "", parent);
            this->Exit();
        }
    }

    void OnButtonPressed(Reference<Button> btn) override
    {
        const auto btnId = btn->GetControlID();
        if (btnId == CMD_BUTTON_CLOSE)
            this->Exit();
        else if (btnId == CMD_BUTTON_DOWNLOAD) {
            ValidateAndDownload();
        }
    }
};

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
{
    // all good
    if (command == "FileDownloader") {
        Reference<Window> parent;

        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++) {
            auto window = desktop->GetChild(i);
            if (window->HasFocus()) {
                parent = window.ToObjectRef<Window>();
                break;
            }
        }

        if (!parent.IsValid()) {
            AppCUI::Dialogs::MessageBox::ShowError("Error!", "Parent window for FileDownloader not valid!");
            return false;
        }

        FileDownloaderWindow dlg(parent);
        dlg.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.FileDownloader"] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::Shift | Input::Key::F2;
}
}
