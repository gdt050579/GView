/**
 * @file RestrictedModeWindow.cpp
 * @brief Window for CTF/exam mode - connects to server for problems and flag submission
 *
 * Connection string format: base64(base64(userid)#base64(serverlocation))
 */

#include "Internal.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>

#undef MessageBox // Windows header conflict with AppCUI

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

namespace
{
    constexpr int CMD_BUTTON_CONNECT      = 1;
    constexpr int CMD_BUTTON_SUBMIT_FLAG  = 2;
    constexpr int CMD_BUTTON_GET_PROBLEMS = 3;
    constexpr int CMD_BUTTON_CLOSE        = 4;

    // RAII wrapper for CURL handle and headers
    class CurlRequest
    {
        CURL* curl = nullptr;
        struct curl_slist* headers = nullptr;
        std::string errorMessage;

      public:
        CurlRequest() : curl(curl_easy_init())
        {
            if (!curl)
            {
                errorMessage = "Failed to initialize CURL";
            }
        }

        ~CurlRequest()
        {
            if (headers)
                curl_slist_free_all(headers);
            if (curl)
                curl_easy_cleanup(curl);
        }

        // Non-copyable
        CurlRequest(const CurlRequest&) = delete;
        CurlRequest& operator=(const CurlRequest&) = delete;

        bool IsValid() const { return curl != nullptr; }
        const std::string& GetError() const { return errorMessage; }

        void SetupPost(const std::string& url, const std::string& userId, const char* body = "")
        {
            if (!curl) return;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

            // Set XAppUserID header
            std::string headerStr = "XAppUserID: " + userId;
            headers = curl_slist_append(headers, headerStr.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        void AddHeader(const char* header)
        {
            if (!curl) return;
            headers = curl_slist_append(headers, header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        void SetWriteCallback(curl_write_callback callback, void* userdata)
        {
            if (!curl) return;
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, userdata);
        }

        bool Perform(long& httpCode)
        {
            if (!curl)
            {
                httpCode = 0;
                return false;
            }

            const CURLcode res = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

            if (res != CURLE_OK)
            {
                errorMessage = "CURL error: " + std::string(curl_easy_strerror(res));
                return false;
            }
            return true;
        }
    };

    // Write callbacks
    size_t WriteToString(char* ptr, size_t size, size_t nmemb, void* userdata)
    {
        std::string* response = static_cast<std::string*>(userdata);
        const size_t totalSize = size * nmemb;
        response->append(ptr, totalSize);
        return totalSize;
    }

    size_t WriteToBuffer(char* ptr, size_t size, size_t nmemb, void* userdata)
    {
        std::vector<uint8>* buffer = static_cast<std::vector<uint8>*>(userdata);
        const size_t totalSize = size * nmemb;
        const uint8* data          = reinterpret_cast<const uint8*>(ptr);
        buffer->insert(buffer->end(), data, data + totalSize);
        return totalSize;
    }

    // Decode base64 string using GView's decoder
    bool DecodeBase64(const std::string& input, std::string& output)
    {
        Buffer decodedBuffer;
        BufferView inputView(reinterpret_cast<const uint8*>(input.data()), static_cast<uint32>(input.size()));
        
        if (!GView::Decoding::Base64::Decode(inputView, decodedBuffer))
        {
            return false;
        }
        
        output.assign(reinterpret_cast<const char*>(decodedBuffer.GetData()), decodedBuffer.GetLength());
        return true;
    }

    // Parse connection string: base64(base64(userid)#base64(serverlocation))
    bool ParseConnectionString(const std::string& connectionString, std::string& userId, std::string& serverLocation)
    {
        std::string outerDecoded;
        if (!DecodeBase64(connectionString, outerDecoded))
            return false;

        const size_t separatorPos = outerDecoded.find('#');
        if (separatorPos == std::string::npos)
            return false;

        const std::string userIdEncoded = outerDecoded.substr(0, separatorPos);
        const std::string serverLocationEncoded = outerDecoded.substr(separatorPos + 1);

        return DecodeBase64(userIdEncoded, userId) && DecodeBase64(serverLocationEncoded, serverLocation);
    }

    // Send HTTP POST request and get string response
    bool SendPostRequest(
        const std::string& url,
        const std::string& userId,
        std::string& response,
        long& httpCode,
        std::string& errorMessage,
        const std::string& body = "",
        bool jsonContentType = false)
    {
        CurlRequest request;
        if (!request.IsValid())
        {
            errorMessage = request.GetError();
            return false;
        }

        request.SetupPost(url, userId, body.c_str());
        if (jsonContentType)
            request.AddHeader("Content-Type: application/json");
        request.SetWriteCallback(WriteToString, &response);

        if (!request.Perform(httpCode))
        {
            errorMessage = request.GetError();
            return false;
        }
        return true;
    }

    // Download binary content from URL
    bool DownloadBinaryContent(
        const std::string& url,
        const std::string& userId,
        std::vector<uint8>& buffer,
        long& httpCode,
        std::string& errorMessage)
    {
        CurlRequest request;
        if (!request.IsValid())
        {
            errorMessage = request.GetError();
            return false;
        }

        request.SetupPost(url, userId);
        request.SetWriteCallback(WriteToBuffer, &buffer);

        if (!request.Perform(httpCode))
        {
            errorMessage = request.GetError();
            return false;
        }
        return true;
    }

} // anonymous namespace

class RestrictedModeWindow : public Window, public Handlers::OnButtonPressedInterface
{
    Reference<TextField> connectionStringField;
    Reference<TextField> flagField;
    Reference<Button> connectButton;
    Reference<Button> submitFlagButton;
    Reference<Button> getProblemsButton;
    Reference<Button> closeButton;
    Reference<Window> parentWindow;

    std::string userId;
    std::string serverLocation;
    bool isConnected;
    bool isCurlInitialized;

  public:
    RestrictedModeWindow(Reference<Window> parent)
        : Window("Restricted Mode", "d:c,w:80,h:16", WindowFlags::Sizeable),
          parentWindow(parent),
          isConnected(false),
          isCurlInitialized(false)
    {
        // Connection string section
        Factory::Label::Create(this, "Connection String:", "l:1,t:1,w:20,h:1");
        connectionStringField = Factory::TextField::Create(this, "", "l:22,t:1,r:15");
        connectButton = Factory::Button::Create(this, "&Connect", "r:1,t:1,w:12", CMD_BUTTON_CONNECT, ButtonFlags::Flat);
        connectButton->Handlers()->OnButtonPressed = this;

        // Flag submission section
        Factory::Label::Create(this, "Flag:", "l:1,t:4,w:20,h:1");
        flagField = Factory::TextField::Create(this, "", "l:22,t:4,r:15");
        submitFlagButton = Factory::Button::Create(this, "&Submit", "r:1,t:4,w:12", CMD_BUTTON_SUBMIT_FLAG, ButtonFlags::Flat);
        submitFlagButton->Handlers()->OnButtonPressed = this;
        submitFlagButton->SetEnabled(false);  // Disabled until connected

        // Get problems section
        Factory::Label::Create(this, "Download and open a problem:", "l:1,t:7,w:30,h:1");
        getProblemsButton = Factory::Button::Create(this, "&Get Problems", "l:32,t:7,w:16", CMD_BUTTON_GET_PROBLEMS, ButtonFlags::Flat);
        getProblemsButton->Handlers()->OnButtonPressed = this;
        getProblemsButton->SetEnabled(false);  // Disabled until connected

        // Status and close
        Factory::Label::Create(this, "Status: Not connected", "l:1,t:10,w:50,h:1");
        closeButton = Factory::Button::Create(this, "C&lose", "l:33,b:0,w:14", CMD_BUTTON_CLOSE, ButtonFlags::Flat);
        closeButton->Handlers()->OnButtonPressed = this;
    }

    void OnButtonPressed(Reference<Button> btn) override
    {
        const auto btnId = btn->GetControlID();
        switch (btnId)
        {
        case CMD_BUTTON_CONNECT:
            HandleConnect();
            break;
        case CMD_BUTTON_SUBMIT_FLAG:
            HandleSubmitFlag();
            break;
        case CMD_BUTTON_GET_PROBLEMS:
            HandleGetProblems();
            break;
        case CMD_BUTTON_CLOSE:
            Exit();
            break;
        }
    }

  private:
    bool InitializeCurl()
    {
        if (!isCurlInitialized)
        {
            if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
            {
                Dialogs::MessageBox::ShowError("Error", "Failed to initialize CURL");
                return false;
            }
            isCurlInitialized = true;
        }
        return true;
    }

    void HandleConnect()
    {
        if (!InitializeCurl())
            return;

        // Get connection string from text field
        std::string connectionString;

        if (!connectionStringField->GetText().ToString(connectionString)) 
        {
            Dialogs::MessageBox::ShowError("Error", "Invalid connection string");
            return;
        }

        if (connectionString.empty())
        {
            Dialogs::MessageBox::ShowError("Error", "Connection string cannot be empty");
            return;
        }

        // Parse the connection string
        if (!ParseConnectionString(connectionString, userId, serverLocation))
        {
            Dialogs::MessageBox::ShowError("Error", "Invalid connection string format.\nExpected: base64(base64(userid)#base64(serverlocation))");
            return;
        }

        // Build URL and send request
        std::string url = serverLocation + "/GView";
        std::string response;
        long httpCode = 0;
        std::string errorMessage;

        if (!SendPostRequest(url, userId, response, httpCode, errorMessage))
        {
            Dialogs::MessageBox::ShowError("Connection Error", errorMessage);
            return;
        }

        if (httpCode == 200)
        {
            isConnected = true;
            submitFlagButton->SetEnabled(true);
            getProblemsButton->SetEnabled(true);
            connectButton->SetEnabled(false);

            Dialogs::MessageBox::ShowNotification("Success", "Connected to server successfully!");
        }
        else
        {
            LocalString<256> msg;
            msg.SetFormat("Server returned HTTP %ld\n\nResponse: %s", httpCode, response.c_str());
            Dialogs::MessageBox::ShowError("Connection Failed", msg);
        }
    }

    void HandleSubmitFlag()
    {
        if (!isConnected)
        {
            Dialogs::MessageBox::ShowError("Error", "Not connected to server");
            return;
        }

        // Get flag from text field
        std::string flag;
        if (!flagField->GetText().ToString(flag))
        {
            Dialogs::MessageBox::ShowError("Error", "Invalid flag conversion");
            return;
        }

        if (flag.empty())
        {
            Dialogs::MessageBox::ShowError("Error", "Flag cannot be empty");
            return;
        }

        // Build URL and send request
        std::string url = serverLocation + "/GView/SubmitFlag";
        
        // Create JSON body with flag
        nlohmann::json requestBody;
        requestBody["flag"] = flag;
        std::string body = requestBody.dump();
        
        std::string response;
        long httpCode = 0;
        std::string errorMessage;

        if (!SendPostRequest(url, userId, response, httpCode, errorMessage, body, true))
        {
            Dialogs::MessageBox::ShowError("Request Error", errorMessage);
            return;
        }

        // Parse response JSON
        try
        {
            auto jsonResponse = nlohmann::json::parse(response);
            std::string status = jsonResponse.value("status", "unknown");
            std::string details = jsonResponse.value("details", "No details provided");

            LocalString<512> msg;
            msg.SetFormat("Status: %s\n\nDetails: %s", status.c_str(), details.c_str());

            if (status == "ok")
            {
                Dialogs::MessageBox::ShowNotification("Flag Submission", msg);
            }
            else
            {
                Dialogs::MessageBox::ShowError("Flag Submission", msg);
            }
        }
        catch (const nlohmann::json::exception& e)
        {
            LocalString<512> msg;
            msg.SetFormat("Failed to parse server response:\n%s\n\nRaw response: %s", e.what(), response.c_str());
            Dialogs::MessageBox::ShowError("Parse Error", msg);
        }
    }

    void HandleGetProblems()
    {
        if (!isConnected)
        {
            Dialogs::MessageBox::ShowError("Error", "Not connected to server");
            return;
        }

        // First, get the list of problems
        std::string url = serverLocation + "/GView/GetProblems";
        std::string response;
        long httpCode = 0;
        std::string errorMessage;

        if (!SendPostRequest(url, userId, response, httpCode, errorMessage))
        {
            Dialogs::MessageBox::ShowError("Request Error", errorMessage);
            return;
        }

        if (httpCode != 200)
        {
            LocalString<256> msg;
            msg.SetFormat("Server returned HTTP %ld", httpCode);
            Dialogs::MessageBox::ShowError("Error", msg);
            return;
        }

        // Parse response JSON to get list of problems
        try
        {
            auto jsonResponse = nlohmann::json::parse(response);
            
            if (!jsonResponse.is_array() || jsonResponse.empty())
            {
                Dialogs::MessageBox::ShowNotification("Info", "No problems available");
                return;
            }

            // Get the first problem
            std::string firstProblem = jsonResponse[0].get<std::string>();

            // Download the problem binary
            std::string problemUrl = serverLocation + "/GView/GetProblems/" + firstProblem;
            std::vector<uint8> binaryBuffer;
            long binaryHttpCode = 0;

            if (!DownloadBinaryContent(problemUrl, userId, binaryBuffer, binaryHttpCode, errorMessage))
            {
                Dialogs::MessageBox::ShowError("Download Error", errorMessage);
                return;
            }

            if (binaryHttpCode != 200)
            {
                LocalString<256> msg;
                msg.SetFormat("Failed to download problem. Server returned HTTP %ld", binaryHttpCode);
                Dialogs::MessageBox::ShowError("Error", msg);
                return;
            }

            if (binaryBuffer.empty())
            {
                Dialogs::MessageBox::ShowError("Error", "Downloaded content is empty");
                return;
            }

            // Open the buffer in GView
            BufferView bufView(binaryBuffer.data(), static_cast<uint32>(binaryBuffer.size()));
            
            // Create a copy of the data since BufferView doesn't own the memory
            Buffer ownedBuffer;
            ownedBuffer.Add(string_view(reinterpret_cast<const char*>(binaryBuffer.data()), binaryBuffer.size()));
            
            GView::App::OpenBuffer(
                ownedBuffer,
                firstProblem,
                firstProblem,
                GView::App::OpenMethod::BestMatch,
                "",
                parentWindow,
                "CTF Problem");

            // Close this window after opening the problem
            Exit();
        }
        catch (const nlohmann::json::exception& e)
        {
            LocalString<512> msg;
            msg.SetFormat("Failed to parse problems list:\n%s", e.what());
            Dialogs::MessageBox::ShowError("Parse Error", msg);
        }
    }
};

void Instance::ShowRestrictedModeWindow()
{
    // Get the current focused window as parent
    Reference<Window> parent;
    auto desktop = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    
    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window = desktop->GetChild(i);
        if (window->HasFocus())
        {
            parent = window.ToObjectRef<Window>();
            break;
        }
    }

    RestrictedModeWindow dlg(parent);
    dlg.Show();
}
