#include <codecvt>
#include <fstream>

#include "Internal.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#undef GetObject
#define BUTTON_1_ID 1

using namespace GView::Utils;
using namespace GView;
using namespace AppCUI::Controls;

using namespace GView::CommonInterfaces::SmartAssistants;

using json = nlohmann::json;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s)
{
    const size_t totalSize = size * nmemb;
    s->append((char*) contents, totalSize);
    return totalSize;
}

std::string callGeminiAPI(const std::string& apiKey, std::string_view prompt, bool& is_ok)
{
    is_ok = true;
    std::string readBuffer;

    CURL* curl = curl_easy_init();
    if (curl) {
        const std::string url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=" + apiKey;

        struct curl_slist* headers = nullptr;
        headers                    = curl_slist_append(headers, "Content-Type: application/json");

        const json payload = { { "contents",
                                 { { "parts",
                                     {
                                           { "text", prompt },
                                     } } } } };

        std::string jsonData = payload.dump();

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        const CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            is_ok = false;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    } else {
        is_ok = false;
    }
    return readBuffer;
}

bool parseGeminiResponse(const std::string& gemini_answer, std::string& responseFound)
{
    try {
        json data                  = json::parse(gemini_answer);
        unsigned int answers_count = (unsigned int) (data["candidates"].size());
        for (unsigned int i = 0; i < answers_count; i++) {
            json answer              = data["candidates"][i];
            json parts               = answer["content"]["parts"];
            unsigned int parts_count = (unsigned int) parts.size();
            for (unsigned int j = 0; j < parts_count; j++) {
                const std::string part = parts[j]["text"];
                responseFound          = part;
                return true;
            }
        }

        responseFound = "No response found! Problems at parsing!";
        return false;

    } catch (...) {
        responseFound = "Error getting/parsing response!";
        return false;
    }
}

//used in debug purposes
//bool ReadBinaryFile(const std::string& fileName, std::vector<char>& content, size_t& size, size_t& nmemb)
//{
//    // Open the file in binary mode
//    std::ifstream inFile(fileName, std::ios::binary);
//    if (!inFile.is_open()) {
//        // std::cerr << "Failed to open file: " << fileName << std::endl;
//        return false;
//    }
//
//    // Read the size and nmemb
//    inFile.read(reinterpret_cast<char*>(&size), sizeof(size));
//    inFile.read(reinterpret_cast<char*>(&nmemb), sizeof(nmemb));
//
//    // Calculate total content size
//    size_t totalSize = size * nmemb;
//
//    // Resize the vector to hold the content
//    content.resize(totalSize);
//
//    // Read the actual content into the vector
//    inFile.read(content.data(), totalSize);
//
//    // Close the file
//    inFile.close();
//
//    return true;
//}

struct GeminiSmartAssistant : SmartAssistantRegisterInterface {
    std::string configData;
    std::string_view GetSmartAssistantName() const override
    {
        return "Gemini";
    }
    std::string_view GetSmartAssistantDescription() const override
    {
        return "Gemini is a smart assistant that can help you with various questions";
    }
    std::string AskSmartAssistant(std::string_view prompt, std::string_view displayPrompt, bool& isSuccess) override
    {
        /*std::vector<char> content;
        size_t size, nmemb;
        bool readed = ReadBinaryFile(R"(D:\repos\GView\bin\Debug\gemini1.data)", content, size, nmemb);
        assert(readed);
        const std::string geminiQuery = std::string(content.data(), content.size());*/

        const std::string geminiQuery = callGeminiAPI(configData, prompt, isSuccess);
        if (!isSuccess) {
            return "Error calling Gemini API!";
        }

        std::string geminiResponse;
        isSuccess = parseGeminiResponse(geminiQuery, geminiResponse);

        return geminiResponse;
    }
    void ReceiveConfigToken(std::string_view configDataParam) override
    {
        this->configData = configDataParam;
    }
};

bool GView::Type::InterfaceTabs::PopulateWindowSmartAssistantsTab(Reference<GView::View::WindowInterface> win)
{
    const auto queryInterface = win->GetQueryInterface();
    queryInterface->RegisterSmartAssistantInterface(Pointer<SmartAssistantRegisterInterface>(new GeminiSmartAssistant));
    return true;
}
