#include <catch.hpp>
#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;

class DummyType : public GView::TypeInterface
{
  public:
    std::string_view GetTypeName() override
    {
        return "Dummy";
    }
    void RunCommand(std::string_view) override
    {
    }
    ~DummyType()
    {
    }

    Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

    uint32 GetSelectionZonesCount() override
    {
        // CHECK(selectionZoneInterface.IsValid(), 0, "");
        return selectionZoneInterface->GetSelectionZonesCount();
    }

    TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        static auto d = TypeInterface::SelectionZone{ 0, 0 };
        // CHECK(selectionZoneInterface.IsValid(), d, "");
        // CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

        return selectionZoneInterface->GetSelectionZone(index);
    }
};

struct ZoneCheckData {
    uint32 indexZoneStart;
    uint32 indexZoneEnd;
    bool shouldHaveName;
};

struct ZoneBeforeLines {
    uint32 zoneIndex;
    uint32 beforeTextLines;
    uint32 beforeAsmLines;
};

class DissasmTestInstance
{
  public:
    Instance* instance;
    std::vector<GView::Object> objects;
    std::unique_ptr<DissasmCodeZone> zone;

    DissasmTestInstance()
    {
        instance = nullptr;
        assert(init());
    }

    bool init()
    {
        auto buffer = AppCUI::OS::File::ReadContent(R"(D:\todo\my_examples\s3\ConsoleApplication5.exeda.data)");
        if (!buffer.IsValid()) {
            printf("ERROR: extract nuffer data from file!");
            return false;
        }
        GView::Utils::DataCache cache = GView::Utils::DataCache();

        std::unique_ptr<AppCUI::OS::File> f = std::make_unique<AppCUI::OS::File>();
        // TODO: add data statically ?
        if (!f->OpenRead(R"(D:\todo\my_examples\s3\ConsoleApplication5.exeda.data)")) {
            printf("ERROR: opening file!");
            return false;
        }

        if (!cache.Init(std::move(f), buffer.GetLength())) {
            printf("ERROR: creating cache!");
            return false;
        }

        objects.push_back(GView::Object(GView::Object::Type::MemoryBuffer, std::move(cache), nullptr, "dummy", "loc", 1));

        initDissasmCodeZone(&objects[0]);
        return true;
    }

    void initDissasmCodeZone(Reference<GView::Object> obj)
    {
        if (!obj.IsValid())
            obj = &objects[0];
        zone                                = std::make_unique<DissasmCodeZone>();
        zone->zoneDetails.language          = DisassemblyLanguage::x86;
        zone->zoneDetails.startingZonePoint = 1024;
        zone->zoneDetails.size              = 5120;
        zone->zoneDetails.entryPoint        = 1034;

        DissasmCodeZoneInitData initData      = {};
        initData.enableDeepScanDissasmOnStart = true;
        initData.maxLocationMemoryMappingSize = 6;
        initData.visibleRows                  = 53;
        initData.obj                          = obj;

        assert(zone->InitZone(initData));
    }

    bool AddCollpasibleZone(uint32 zoneListStart, uint32 zoneLineEnd)
    {
        return zone->AddCollapsibleZone(zoneListStart, zoneLineEnd, false);
    }

    bool CheckInternalTypes(uint32 zoneIndex, std::initializer_list<ZoneCheckData> zones)
    {
        if (zoneIndex >= zone->dissasmType.internalTypes.size() && zoneIndex != -1u) {
            printf("ERROR: invalid zone index %d >= %llu", zoneIndex, zone->dissasmType.internalTypes.size());
            return false;
        }

        std::vector<DissasmCodeInternalType>* childrenToCheck = &zone->dissasmType.internalTypes;
        if (zoneIndex != -1u)
            childrenToCheck = &zone->dissasmType.internalTypes[zoneIndex].internalTypes;

        if (childrenToCheck->size() != zones.size()) {
            printf("ERROR: invalid zone length %d >= %llu", zoneIndex, childrenToCheck->size());
            return false;
        }

        auto it = childrenToCheck->begin();
        for (auto& z : zones) {
            if (it->indexZoneStart != z.indexZoneStart || it->indexZoneEnd != z.indexZoneEnd || !it->name.empty() != z.shouldHaveName) {
                printf(
                      "ERROR: zone %d<->%d, %d<->%d, %d<->%d",
                      it->indexZoneStart,
                      z.indexZoneStart,
                      it->indexZoneEnd,
                      z.indexZoneEnd,
                      !it->name.empty(),
                      z.shouldHaveName);
                return false;
            }
            ++it;
        }
        return true;
    }

    bool CheckBeforeLinesData(uint32 zoneIndex, std::initializer_list<ZoneBeforeLines> zones)
    {
        if (zoneIndex >= zone->dissasmType.internalTypes.size() && zoneIndex != -1u) {
            printf("ERROR: invalid zone index %d >= %llu", zoneIndex, zone->dissasmType.internalTypes.size());
            return false;
        }

        std::vector<DissasmCodeInternalType>* childrenToCheck = &zone->dissasmType.internalTypes;
        if (zoneIndex != -1u)
            childrenToCheck = &zone->dissasmType.internalTypes[zoneIndex].internalTypes;

        for (auto& z : zones) {
            if (z.zoneIndex >= childrenToCheck->size()) {
                printf("ERROR: invalid zone index %d >= %llu", z.zoneIndex, childrenToCheck->size());
                return false;
            }
            const auto& it = (*childrenToCheck)[z.zoneIndex];

            if (!it.IsValidDataLine()) {
                printf("ERROR: invalid data line for zone %d, %d<->%d != %d", z.zoneIndex, it.beforeTextLines, it.beforeAsmLines, it.indexZoneStart);
                return false;
            }

            if (it.beforeTextLines != z.beforeTextLines || it.beforeAsmLines != z.beforeAsmLines) {
                printf("ERROR: zone %d<->%d, %d<->%d", it.beforeTextLines, z.beforeTextLines, it.beforeAsmLines, z.beforeAsmLines);
                return false;
            }
        }
        return true;
    }

    void ReachZoneLine(uint32 zoneLine)
    {
        zone->ReachZoneLine(zoneLine);
    }

    DissasmAsmPreCacheLine GetCurrentAsmLine(uint32 line)
    {
        auto val = zone->GetCurrentAsmLine(line, &objects[0]);
        return val;
    }

    bool CheckLineMnemonic(uint32 line, std::string_view mnemonic)
    {
        auto val = zone->GetCurrentAsmLine(line, &objects[0]);
        printf("[%u]mnemonic: %s\n", line, val.mnemonic);
        return val.mnemonic == mnemonic;
    }

    ~DissasmTestInstance()
    {
        delete instance;
    }
};

TEST_CASE("DissasmCollapsible", "[Dissasm]")
{
    DissasmTestInstance dissasmInstance;

    REQUIRE(dissasmInstance.AddCollpasibleZone(2, 5));
    REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2 }, { 2, 5, true }, { 5, 4571 } }));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 2 }, { 2, 0, 5 } }));

    REQUIRE(!dissasmInstance.AddCollpasibleZone(2, 5));
    REQUIRE(!dissasmInstance.AddCollpasibleZone(1, 4));

    REQUIRE(dissasmInstance.AddCollpasibleZone(0, 2));
    REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, 4571 } }));

    REQUIRE(dissasmInstance.AddCollpasibleZone(5, 11));
    REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, 11, true }, { 11, 4571 } }));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 2 }, { 2, 0, 5 }, { 3, 2, 9 } }));

    REQUIRE(dissasmInstance.AddCollpasibleZone(7, 9));
    REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, 11, true }, { 11, 4571 } }));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 2 }, { 2, 0, 5 }, { 3, 2, 9 } }));
    REQUIRE(dissasmInstance.CheckInternalTypes(2, { { 5, 7 }, { 7, 9, true }, { 9, 11 } }));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(2, { { 0, 0, 5 }, { 1, 1, 6 }, { 2, 2, 7 } }));

    REQUIRE(dissasmInstance.CheckLineMnemonic(0, "int3"));
    REQUIRE(dissasmInstance.CheckLineMnemonic(1, "int3"));
    REQUIRE(dissasmInstance.CheckLineMnemonic(2, "int3"));
    REQUIRE(dissasmInstance.CheckLineMnemonic(3, "int3"));
    REQUIRE(dissasmInstance.CheckLineMnemonic(4, "int3"));

    // dissasmInstance.ReachZoneLine(0);
    // dissasmInstance.GetCurrentAsmLine(0);
}