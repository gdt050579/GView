#include "HashAnalyzer.hpp"
#include "ServiceInterface.hpp"
#include "VirusTotalService.hpp"
#include "HttpClient.hpp"

#include <mutex>

namespace GView::GenericPlugins::HashAnalyzer
{
constexpr int32 CMD_BUTTON_CLOSE   = 1;
constexpr int32 CMD_BUTTON_COMPUTE = 2;

constexpr std::string_view CMD_SHORT_NAME = "HashAnalyzer";
constexpr std::string_view CMD_FULL_NAME  = "Command.HashAnalyzer";

HashAnalyzerDialog::HashAnalyzerDialog(Reference<GView::Object> obj) : Window("Hash Analyzer", "d:c,w:70,h:20", WindowFlags::ProcessReturn)
{
    this->object = obj;

    for (auto i = 0U; i < this->object->GetContentType()->GetSelectionZonesCount(); i++)
    {
        selectedZones.emplace_back(this->object->GetContentType()->GetSelectionZone(i));
    }

    computeForFile      = Factory::RadioBox::Create(this, "Compute for the &entire file", "x:1,y:1,w:31", 1);
    computeForSelection = Factory::RadioBox::Create(this, "Compute for the &selection", "x:1,y:2,w:31", 1);

    if (selectedZones.empty())
    {
        computeForFile->SetChecked(true);
        computeForSelection->SetEnabled(false);
    }
    else
    {
        computeForSelection->SetChecked(true);
    }

    hashesList = Factory::ListView::Create(this, "l:1,t:4,r:1,b:4", { "n:Type,w:10", "n:Value,w:55" });

    computeBtn                      = Factory::Button::Create(this, "&Compute", "l:1,b:0,w:15", CMD_BUTTON_COMPUTE);
    computeBtn->Handlers()->OnButtonPressed = this;

    close                              = Factory::Button::Create(this, "&Close", "r:1,b:0,w:15", CMD_BUTTON_CLOSE);
    close->Handlers()->OnButtonPressed = this;
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
        hashesList->AddItem({ "MD5", md5.GetHexValue() });
        
        sha1.Final();
        hashesList->AddItem({ "SHA1", sha1.GetHexValue() });
        
        sha256.Final();
        hashesList->AddItem({ "SHA256", sha256.GetHexValue() });
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