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

GVIEW_PLUGIN_ENTRY_POINTS
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

    // the PCAP vocabulary of HDF.json, resolved once per window; the plugin instance is the tool that executes
    // <CheckConnections>(x) and <ExtractConnectionData>(c) for the subjects of this capture
    void InitHDF(Reference<GView::View::WindowInterface> win, Reference<PCAP::PCAPFile> pcap)
    {
        auto hdf = win->GetHDF();
        if (!hdf.IsValid())
            return;
        const std::string_view predicateNames[] = { "IsPCAP", "HasNetworkConnections", "HasConnectionWithExecutable", "HasConnectionWithScript" };
        const std::string_view actionNames[]    = { "CheckConnections", "ExtractConnectionData" };
        HDF::PredicateId p[std::size(predicateNames)];
        HDF::ActionId a[std::size(actionNames)];
        HDF::EngineInterface::Lookup report;
        hdf->LookupPredicates(predicateNames, p, &report);
        hdf->LookupActions(actionNames, a, &report);
        for ([[maybe_unused]] const auto& missing : report.missing)
            LOG_ERROR("HDF: the PCAP symbol %s is not declared in HDF.json", missing.c_str());
        pcap->predicates.IsPCAP                      = p[0];
        pcap->predicates.HasNetworkConnections       = p[1];
        pcap->predicates.HasConnectionWithExecutable = p[2];
        pcap->predicates.HasConnectionWithScript     = p[3];
        pcap->actions.CheckConnections               = a[0];
        pcap->actions.ExtractConnectionData          = a[1];
        pcap->hdf                                    = hdf;
        const auto subject                           = win->GetSubject();
        for (const auto action : a)
            if (action != HDF::INVALID_ACTION_ID)
                hdf->RegisterActionExecutor(action, subject, Reference<HDF::ActionExecutorInterface>(pcap.operator->()));
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pcap = win->GetObject()->GetContentType<PCAP::PCAPFile>();
        pcap->InitStreamManager(win);
        pcap->RegisterPayloadParser(std::make_unique<PCAP::HTTP::HTTPParser>());
        pcap->Update();

        // everything disclosed here is part of Init_T(x), the initial extraction the core opened for the window's subject
        InitHDF(win, pcap);
        const auto subject = win->GetSubject();
        if (pcap->hdf.IsValid() && HDF::EngineInterface::IsValid(pcap->predicates.IsPCAP))
            pcap->hdf->Disclose(subject, pcap->predicates.IsPCAP, { subject }, "parsed the PCAP header");

        // add views
        CreateContainerView(win, pcap);
        CreateBufferView(win, pcap);

        // the streams are known once the container view enumerated the packets
        if (pcap->hdf.IsValid() && !pcap->streamManager.empty() && HDF::EngineInterface::IsValid(pcap->predicates.HasNetworkConnections))
            pcap->hdf->Disclose(
                  subject, pcap->predicates.HasNetworkConnections, { subject, static_cast<uint64>(pcap->streamManager.size()) }, "parsed the PCAP file");

        // add panels
        win->AddPanel(Pointer<TabPage>(new PCAP::Panels::Information(win->GetObject(), pcap)), true);
        win->AddPanel(Pointer<TabPage>(new PCAP::Panels::Packets(pcap, win)), false);

        return true;
    }

    // static metadata: the HDF vocabulary the PCAP plugin discloses and the actions it executes
    PLUGIN_EXPORT void RegisterPlugin(Reference<GView::PluginRegistry> registry)
    {
        auto& v = registry->HDFVocabulary();
        v.Predicate("IsPCAP", { { "x", "Subject" } }, "{x} is a network capture");
        v.Predicate("HasNetworkConnections", { { "x", "Subject" }, { "count", "Int" } }, "{x} has {count} connections");
        v.Predicate("HasConnectionWithExecutable", { { "c", "Subject" }, { "name", "String" } }, "connection {c} transfers the executable {name}");
        v.Predicate("HasConnectionWithScript", { { "c", "Subject" }, { "name", "String" } }, "connection {c} transfers the script {name}");
        v.Action("CheckConnections", { { "x", "Subject" } }, "Identify the connections in {x}");
        v.Action("ExtractConnectionData", { { "c", "Subject" } }, "Extract the data transferred over {c}");
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]     = { "magic:A1 B2 C3 D4", "magic:D4 C3 B2 A1" };
        sect["Extension"]   = "pcap";
        sect["Priority"]    = 1;
        sect["Description"] = "Network Packet capture file format";
    }
}
