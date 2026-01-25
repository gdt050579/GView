#include "HashAnalyzer.hpp"
#include "VirusTotalService.hpp"
#include "HttpClient.hpp"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

#include <mutex>

#undef MessageBox

namespace GView::GenericPlugins::HashAnalyzer
{
constexpr int32 CMD_BUTTON_CLOSE   = 1;
constexpr int32 CMD_BUTTON_COMPUTE = 2;
constexpr int32 CMD_BUTTON_ANALYZE = 3;
constexpr int32 CMD_BUTTON_OPEN_LINK = 4;

constexpr std::string_view CMD_SHORT_NAME = "HashAnalyzer";
constexpr std::string_view CMD_FULL_NAME  = "Command.HashAnalyzer";

// ============================================================================
// AnalysisResultsDialog Implementation
// ============================================================================

AnalysisResultsDialog::AnalysisResultsDialog(const AnalysisResult& result)
    : Window("Analysis Results", "d:c,w:80,h:24", WindowFlags::ProcessReturn),
      storedResult(result)
{
    // Summary List
    Factory::Label::Create(this, "Summary", "x:1,y:1,w:10");
    auto summaryList = Factory::ListView::Create(this, "l:1,t:2,r:1,h:7", { "n:Property,w:20", "n:Value,w:54" });
    
    summaryList->AddItem({ "Service", result.serviceName });
    
    std::string detectionStr = std::to_string(result.detectionCount) + " / " + std::to_string(result.totalEngines);
    if (result.detectionCount > 0) detectionStr += " (DETECTED)";
    summaryList->AddItem({ "Detection", detectionStr });

    summaryList->AddItem({ "Scan Date", result.scanDate });
    summaryList->AddItem({ "File Type", result.fileType });
    summaryList->AddItem({ "File Size", std::to_string(result.fileSize) + " bytes" });
    if (!result.permalink.empty())
    {
        summaryList->AddItem({ "Link", result.permalink });
    }

    // Vendor Results List
    Factory::Label::Create(this, "Vendor Results", "x:1,y:10,w:20");
    resultsList = Factory::ListView::Create(this, "l:1,t:11,r:1,b:4", { "n:Vendor,w:20", "n:Result,w:54" });
    
    if (result.found)
    {
        for (const auto& [vendor, detection] : result.vendorResults)
        {
            resultsList->AddItem({ vendor, detection });
        }
    }
    else
    {
         resultsList->AddItem({ "Info", "No results found or file not in database." });
    }

    // Buttons
    if (!result.permalink.empty())
    {
        Factory::Button::Create(this, "Open &Report", "l:1,b:0,w:15", CMD_BUTTON_OPEN_LINK)->Handlers()->OnButtonPressed = this;
    }
    closeBtn = Factory::Button::Create(this, "&Close", "r:1,b:0,w:15", CMD_BUTTON_CLOSE);
    closeBtn->Handlers()->OnButtonPressed = this;
    closeBtn->SetFocus();
}

void AnalysisResultsDialog::OnButtonPressed(Reference<Button> b)
{
    if (b->GetControlID() == CMD_BUTTON_CLOSE)
    {
        Exit();
    }
    else if (b->GetControlID() == CMD_BUTTON_OPEN_LINK)
    {
#ifdef _WIN32
        ShellExecuteA(NULL, "open", storedResult.permalink.c_str(), NULL, NULL, SW_SHOWNORMAL);
#endif
    }
}

// ============================================================================
// HashAnalyzerDialog Implementation
// ============================================================================

HashAnalyzerDialog::HashAnalyzerDialog(Reference<GView::Object> obj) 
    : Window("Hash Analyzer", "d:c,w:80,h:16", WindowFlags::ProcessReturn),
      hashesComputed(false)
{
    this->object = obj;

    for (auto i = 0U; i < this->object->GetContentType()->GetSelectionZonesCount(); i++)
    {
        selectedZones.emplace_back(this->object->GetContentType()->GetSelectionZone(i));
    }

    // Radio buttons for file/selection choice
    computeForFile      = Factory::RadioBox::Create(this, "Compute for the &entire file", "x:1,y:1,w:35", 1);
    computeForSelection = Factory::RadioBox::Create(this, "Compute for the &selection", "x:1,y:2,w:35", 1);

    if (selectedZones.empty())
    {
        computeForFile->SetChecked(true);
        computeForSelection->SetEnabled(false);
    }
    else
    {
        computeForSelection->SetChecked(true);
    }

    // Hash list for computed hashes
    hashesList = Factory::ListView::Create(this, "l:1,t:4,r:1,h:5", { "n:Type,w:10", "n:Value,w:65" });

    // Service selection
    serviceLabel = Factory::Label::Create(this, "&Service:", "x:1,y:10,w:10");
    serviceSelector = Factory::ComboBox::Create(this, "x:11,y:10,w:40");
    PopulateServiceSelector();

    // Buttons
    computeBtn = Factory::Button::Create(this, "&Compute", "l:1,b:0,w:15", CMD_BUTTON_COMPUTE);
    computeBtn->Handlers()->OnButtonPressed = this;

    analyzeBtn = Factory::Button::Create(this, "&Analyze", "l:18,b:0,w:15", CMD_BUTTON_ANALYZE);
    analyzeBtn->Handlers()->OnButtonPressed = this;
    analyzeBtn->SetEnabled(false); // Disabled until hashes are computed

    closeBtn = Factory::Button::Create(this, "C&lose", "r:1,b:0,w:15", CMD_BUTTON_CLOSE);
    closeBtn->Handlers()->OnButtonPressed = this;
}

void HashAnalyzerDialog::PopulateServiceSelector()
{
    const auto& services = ServiceManager::Get().GetServices();
    for (const auto& svc : services)
    {
        serviceSelector->AddItem(svc->GetName());
    }
    if (!services.empty())
    {
        serviceSelector->SetCurentItemIndex(0);
    }
}

void HashAnalyzerDialog::OnButtonPressed(Reference<Button> b)
{
    if (b->GetControlID() == CMD_BUTTON_CLOSE)
    {
        Exit();
    }
    else if (b->GetControlID() == CMD_BUTTON_COMPUTE)
    {
        ComputeHash();
    }
    else if (b->GetControlID() == CMD_BUTTON_ANALYZE)
    {
        OnAnalyze();
    }
}

bool HashAnalyzerDialog::OnEvent(Reference<Control> c, Event eventType, int id)
{
    if (Window::OnEvent(c, eventType, id))
    {
        return true;
    }

    if (eventType == Event::WindowAccept)
    {
        if (hashesComputed)
        {
            OnAnalyze();
        }
        else
        {
            ComputeHash();
        }
        return true;
    }

    return false;
}

void HashAnalyzerDialog::OnAnalyze()
{
    if (!hashesComputed)
    {
        Dialogs::MessageBox::ShowError("Error", "Please compute hashes first.");
        return;
    }

    const auto& services = ServiceManager::Get().GetServices();
    if (services.empty())
    {
        Dialogs::MessageBox::ShowError("Error", "No analysis services available.");
        return;
    }

    auto selectedIdx = serviceSelector->GetCurrentItemIndex();
    if (selectedIdx == ComboBox::NO_ITEM_SELECTED || selectedIdx >= services.size())
    {
        Dialogs::MessageBox::ShowError("Error", "Please select an analysis service.");
        return;
    }

    IAnalysisService* service = services[selectedIdx].get();
    
    if (!service->IsConfigured())
    {
        Dialogs::MessageBox::ShowError("Error", "The selected service is not configured. Please set up your API key.");
        return;
    }

    // Perform the analysis (this is blocking)
    AnalysisResult result = service->AnalyzeHash(sha256Hash, HashKind::SHA256);

    if (!result.success)
    {
        Dialogs::MessageBox::ShowError("API Error", result.errorMessage);
        return;
    }

    // Close this dialog and open the results dialog
    Exit();
    
    AnalysisResultsDialog resultsDialog(result);
    resultsDialog.Show();
}

static std::once_flag g_servicesInitFlag;

static void RegisterServices()
{
    std::call_once(g_servicesInitFlag, []() {
        // Register VirusTotal service provider
        GView::GenericPlugins::HashAnalyzer::ServiceManager::Get().RegisterService(
            std::make_unique<GView::GenericPlugins::HashAnalyzer::VirusTotalService>());
    });
}

void HashAnalyzerDialog::ComputeHash()
{
    const auto computeForFileOpt = computeForFile->IsChecked();
    auto objectSize = 0ULL;
    if (computeForFileOpt)
    {
        objectSize = object->GetData().GetSize();
    }
    else
    {
        for (auto& sz : selectedZones)
        {
            objectSize += sz.end - sz.start + 1;
        }
    }

    ProgressStatus::Init("Computing...", objectSize);

    GView::Hashes::OpenSSLHash md5(GView::Hashes::OpenSSLHashKind::Md5);
    GView::Hashes::OpenSSLHash sha1(GView::Hashes::OpenSSLHashKind::Sha1);
    GView::Hashes::OpenSSLHash sha256(GView::Hashes::OpenSSLHashKind::Sha256);

    LocalString<512> ls;
    const char* format = "Reading [0x%.8llX/0x%.8llX] bytes...";
    if (objectSize > 0xFFFFFFFF)
    {
        format = "[0x%.16llX/0x%.16llX] bytes...";
    }

    const auto block = object->GetData().GetCacheSize();
    
    auto UpdateHashesOnBuffer = [&](const Buffer& buffer) -> bool
    {
        CHECK(md5.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha1.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        CHECK(sha256.Update(buffer.GetData(), static_cast<uint32>(buffer.GetLength())), false, "");
        return true;
    };

    auto UpdateHashesOnBlock = [&](uint64 offset, uint64 left) -> bool
    {
        do
        {
             if (ProgressStatus::Update(offset, ls.Format(format, offset, objectSize)))
             {
                 return false;
             }

            const auto sizeToRead = (left >= block ? block : left);
            left -= (left >= block ? block : left);

            const Buffer buffer = object->GetData().CopyToBuffer(offset, static_cast<uint32>(sizeToRead), true);
            CHECK(buffer.IsValid(), false, "");

            CHECK(UpdateHashesOnBuffer(buffer), false, "");

            offset += sizeToRead;
        } while (left > 0);
        return true;
    };

    bool success = true;
    if (computeForFileOpt)
    {
        success = UpdateHashesOnBlock(0, object->GetData().GetSize());
    }
    else
    {
        for (auto& sz : selectedZones)
        {
             if (!UpdateHashesOnBlock(sz.start, sz.end - sz.start + 1))
             {
                 success = false;
                 break;
             }
        }
    }
    
    if (success)
    {
        hashesList->DeleteAllItems();
        
        md5.Final();
        md5Hash = md5.GetHexValue();
        hashesList->AddItem({ "MD5", md5Hash });
        
        sha1.Final();
        sha1Hash = sha1.GetHexValue();
        hashesList->AddItem({ "SHA1", sha1Hash });
        
        sha256.Final();
        sha256Hash = sha256.GetHexValue();
        hashesList->AddItem({ "SHA256", sha256Hash });

        hashesComputed = true;
        analyzeBtn->SetEnabled(true);
    }
}
} // namespace GView::GenericPlugins::HashAnalyzer

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    GView::GenericPlugins::HashAnalyzer::RegisterServices();

    if (command == GView::GenericPlugins::HashAnalyzer::CMD_SHORT_NAME) {
        GView::GenericPlugins::HashAnalyzer::HashAnalyzerDialog dlg(object);
        dlg.Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect[GView::GenericPlugins::HashAnalyzer::CMD_FULL_NAME] = Input::Key::Ctrl | Input::Key::Alt | Input::Key::H;
}
}