#include "PCAP.hpp"
#include "PayloadParsers/HttpParser.hpp"
#include <array>
#include <cassert>

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

constexpr string_view PCAP_ICON = "WWWWWWW.WWWWWWW."  // 1
                                  "W.....W.W......."  // 2
                                  "W.....W.W......."  // 3
                                  "W.....W.W......."  // 4
                                  "WWWWWWW.W......."  // 5
                                  "W.......W......."  // 6
                                  "W.......WWWWWWW."  // 7
                                  "................"  // 8
                                  "WWWWWWW.WWWWWWW."  // 9
                                  "W.....W.W.....W."  // 10
                                  "W.....W.W.....W."  // 11
                                  "W.....W.W.....W."  // 12
                                  "WWWWWWW.WWWWWWW."  // 13
                                  "W.....W.W......."  // 14
                                  "W.....W.W......."  // 15
                                  "W.....W.W......."; // 16

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        CHECK(buf.GetLength() > sizeof(PCAP::Header), false, "");

        auto header = buf.GetObject<PCAP::Header>(0);
        CHECK(header.IsValid(), false, "");

        CHECK(header->magicNumber == PCAP::Magic::Identical || header->magicNumber == PCAP::Magic::Swapped, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new PCAP::PCAPFile();
    }

    static constexpr auto DarkGreenBlue = ColorPair{ Color::DarkGreen, Color::DarkBlue };
    static constexpr auto DarkRedBlue   = ColorPair{ Color::DarkRed, Color::DarkBlue };
    constexpr static auto colors        = std::array<ColorPair, 2>{ DarkGreenBlue, DarkRedBlue };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PCAP::PCAPFile> pcap)
    {
        BufferViewer::Settings settings;
        
        auto offset = 0ULL;
        settings.AddZone(offset, sizeof(pcap->header), ColorPair{ Color::Magenta, Color::DarkBlue }, "Header");
        offset += sizeof(pcap->header);

        auto count = 0;
        LocalString<32> ls;
        for (const auto& [header, offset] : pcap->packetHeaders)
        {
            const auto& c = *(colors.begin() + (count % 2));
            settings.AddZone(offset, sizeof(PCAP::PacketHeader) + header->inclLen, c, ls.Format("Packet_%u", count));
            count++;
        }

        pcap->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<GView::Type::PCAP::PCAPFile> pcap)
    {
        ContainerViewer::Settings settings;

        settings.SetName("StreamView");
        settings.SetIcon(PCAP_ICON);
        settings.SetColumns({
              "n:&ID,a:l,w:8",
              "n:&Connection,a:l,w:50",
              "n:&IpProt.,a:c,w:8",
              "n:&Transport,a:c,w:12",
              "n:&Payload,a:r,w:9",
              "n:&AppLayer,a:c,w:10",
              "n:&Summary,a:l,w:50",
        });

        settings.SetEnumerateCallback(win->GetObject()->GetContentType<GView::Type::PCAP::PCAPFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
        settings.SetOpenItemCallback(win->GetObject()->GetContentType<GView::Type::PCAP::PCAPFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

        for (const auto& [header, offset] : pcap->packetHeaders)
            pcap->streamManager.AddPacket(header, pcap->header.network);
        pcap->streamManager.FinishedAdding();

		const auto properties = pcap->GetPropertiesForContainerView();
        for (const auto& property : properties)
            settings.AddProperty(property.first.data(), property.second.data());

        win->CreateViewer(settings);
    }

    bool InitPredicates(Reference<GView::View::WindowInterface> win, Reference<PCAP::PCAPFile> pcap)
    {
        auto engine = win->GetAnalysisEngine();
        if (!engine.IsValid())
            return false;
        std::vector<Components::AnalysisEngine::PredId*> preds = { &pcap->predicates.IsPCAP,
                                                                   &pcap->predicates.HasNetworkConnections,
                                                                   &pcap->predicates.HasConnectionWithExecutable,
                                                                   &pcap->predicates.HasConnectionWithScript };
        std::vector<std::string_view> predNames                = { "IsPCAP",
                                                                   "HasNetworkConnections",
                                                                   "HasConnectionWithExecutable",
                                                                   "HasConnectionWithScript"};
        bool res_value                                         = true;
        for (uint32 i = 0; i < predNames.size(); i++) {
            const auto& p = predNames[i];
            auto res      = engine->GetPredId(p);
            if (Components::AnalysisEngine::AnalysisEngineInterface::IsValidPredicateId(res)) {
                *preds[i] = res;
            } else {
                AppCUI::Dialogs::MessageBox::ShowError("Failed to get predicate", p);
                res_value = false;
            }
        }
        pcap->analysisEngine = engine;
        return res_value;
    }

    void SendInitialPredicates(Reference<GView::View::WindowInterface> win, Reference<PCAP::PCAPFile> pcap)
    {
        if (pcap->streamManager.empty())
            return;
        {
            auto subject                           = win->GetCurrentWindowSubject();

            std::vector<Components::AnalysisEngine::Arg> args = { { "count", pcap->streamManager.size() } };

            const auto has_network_connection_fact = Components::AnalysisEngine::AnalysisEngineInterface::CreateFactFromPredicateAndSubject(
                  pcap->predicates.HasNetworkConnections, subject, "static analysis", "parsed the PCAP file", args);

            auto res = pcap->analysisEngine->SubmitFact(has_network_connection_fact);
            if (!res) {
                LOG_ERROR("Failed to add IsPCAP fact");
            }
        }
        std::vector<Components::AnalysisEngine::ActId> actions;
        auto checkConnectionAction = pcap->analysisEngine->GetActId("CheckNetworkConnections");
        if (Components::AnalysisEngine::AnalysisEngineInterface::IsValidActionId(checkConnectionAction)) {
            pcap->actions.CheckNetworkConnections = checkConnectionAction;
            actions.push_back(checkConnectionAction);
        }

        auto viewConnectionWithExecutableAction = pcap->analysisEngine->GetActId("ViewExecutableFromConnection");
        if (Components::AnalysisEngine::AnalysisEngineInterface::IsValidActionId(viewConnectionWithExecutableAction)) {
            pcap->actions.ViewExecutableFromConnection = viewConnectionWithExecutableAction;
            actions.push_back(viewConnectionWithExecutableAction);
        }

        auto viewConnectionWithScriptAction= pcap->analysisEngine->GetActId("ViewScriptFromConnection");
        if (Components::AnalysisEngine::AnalysisEngineInterface::IsValidActionId(viewConnectionWithScriptAction)) {
            pcap->actions.ViewScriptFromConnection = viewConnectionWithScriptAction;
            actions.push_back(viewConnectionWithScriptAction);
        }

        auto results = pcap->analysisEngine->RegisterActionTrigger(actions, pcap.ToObjectRef<Components::AnalysisEngine::RuleTriggerInterface>());
        for (size_t i = 0; i < results.size(); i++) {
            if (results[i] == false) {
                LOG_ERROR("Failed to register action trigger for action id {}", actions[i]);
                assert(false);
            }
        }
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pcap = win->GetObject()->GetContentType<PCAP::PCAPFile>();
        pcap->InitStreamManager(win);
        pcap->RegisterPayloadParser(std::make_unique<PCAP::HTTP::HTTPParser>());
        pcap->Update();

        auto u16_name = win->GetObject()->GetName();
        std::string file_name = {};
        UnicodeStringBuilder sb(u16_name);
        sb.ToString(file_name);
        if (file_name.empty())
            file_name = "Unknown";

        const bool has_init_predicates = InitPredicates(win, pcap);
        if (has_init_predicates) {
            auto subject      = win->GetCurrentWindowSubject();

            std::vector<Components::AnalysisEngine::Arg> args = { { "filename", file_name } };

            auto is_pcap_fact = Components::AnalysisEngine::AnalysisEngineInterface::CreateFactFromPredicateAndSubject(
                  pcap->predicates.IsPCAP, subject, "static analysis", "parsed the PCAP header", args);
            auto res = pcap->analysisEngine->SubmitFact(is_pcap_fact);
            if (!res) {
                LOG_ERROR("Failed to add IsPCAP fact");
            }
        }

        // add views
        CreateContainerView(win, pcap);
        CreateBufferView(win, pcap);

        if (has_init_predicates) {
            SendInitialPredicates(win, pcap);
        }

        // add panels
        win->AddPanel(Pointer<TabPage>(new PCAP::Panels::Information(win->GetObject(), pcap)), true);
        win->AddPanel(Pointer<TabPage>(new PCAP::Panels::Packets(pcap, win)), false);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]     = { "magic:A1 B2 C3 D4", "magic:D4 C3 B2 A1" };
        sect["Extension"]   = "pcap";
        sect["Priority"]    = 1;
        sect["Description"] = "Network Packet capture file format";
    }
}
