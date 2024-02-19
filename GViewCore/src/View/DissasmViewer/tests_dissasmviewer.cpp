#include <catch.hpp>
#include "DissasmViewer.hpp"
#include "DissasmX86.hpp"
#include <array>

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
    bool CheckLinesWorkingIndexesSameAsZonesRecursive(std::vector<DissasmCodeInternalType>* childrenToCheck)
    {
        if (!childrenToCheck)
            return true;

        for (auto& z : *childrenToCheck) {
            if (z.indexZoneStart != z.workingIndexZoneStart || z.indexZoneEnd != z.workingIndexZoneEnd) {
                printf(
                      "CheckLinesWorkingIndexesSameAsZonesRecursive ERROR: zone %d<->%d, %d<->%d",
                      z.indexZoneStart,
                      z.workingIndexZoneStart,
                      z.indexZoneEnd,
                      z.workingIndexZoneEnd);
                return false;
            }
            if (!z.internalTypes.empty())
                if (!CheckLinesWorkingIndexesSameAsZonesRecursive(&z.internalTypes))
                    return false;
        }

        return true;
    }

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
        return zone->AddCollapsibleZone(zoneListStart, zoneLineEnd);
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

            // if (!it.IsValidDataLine()) {
            //     printf("ERROR: !IsValidDataLine for zone %d, %d<->%d != %d", z.zoneIndex, it.beforeTextLines, it.beforeAsmLines, it.indexZoneStart);
            //     return false;
            // }

            if (it.beforeTextLines != z.beforeTextLines || it.beforeAsmLines != z.beforeAsmLines) {
                printf("ERROR: [%d]zone: %d<->%d, %d<->%d", z.zoneIndex, it.beforeTextLines, z.beforeTextLines, it.beforeAsmLines, z.beforeAsmLines);
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
        auto val = zone->GetCurrentAsmLine(line, &objects[0], nullptr);
        return val;
    }

    bool CheckLineMnemonic(uint32 line, std::string_view mnemonic)
    {
        auto val = zone->GetCurrentAsmLine(line, &objects[0], nullptr);
        if (val.mnemonic != mnemonic) {
            printf("[%u]mnemonic: %s\n", line, val.mnemonic);
            return false;
        }
        return true;
    }

    bool CheckLineOpStr(uint32 line, std::string_view startWithStr)
    {
        auto val = zone->GetCurrentAsmLine(line, &objects[0], nullptr);
        if (!std::string_view(val.op_str, val.op_str_size).starts_with(startWithStr)) {
            printf("[%u]op_str: %s\n", line, val.op_str);
            return false;
        }
        return true;
    }

    bool CheckLinesWorkingIndexesSameAsZones()
    {
        return CheckLinesWorkingIndexesSameAsZonesRecursive(&zone->dissasmType.internalTypes);
    }

    bool CheckCollapseOrExtendZone(uint32 zoneLine, DissasmCodeZone::CollapseExpandType collapse)
    {
        int32 difference = 0;
        return zone->CollapseOrExtendZone(zoneLine, collapse, difference);
    }

    void PrintInstructions(uint32 count)
    {
        for (uint32 i = 0; i < count; i++) {
            auto val = zone->GetCurrentAsmLine(i, &objects[0], nullptr);
            printf("[%u] %s %s\n", i, val.mnemonic, val.op_str);
        }
    }

    bool CheckLineMnemonicArray(uint32 startingLine, uint32 count, const char** mnemonicArray)
    {
        for (uint32 i = 0; i < count; i++) {
            auto val = zone->GetCurrentAsmLine(startingLine + i, &objects[0], nullptr);
            if (strcmp(val.mnemonic, mnemonicArray[i]) != 0) {
                printf("[%u]expected mnemonic:%s, found mnemonic: %s\n", startingLine + i, mnemonicArray[i], val.mnemonic);
                return false;
            }
        }
        return true;
    }

    ~DissasmTestInstance()
    {
        delete instance;
    }
};

TEST_CASE("DissasmFunctions", "[Dissasm]")
{
    uint64 value = 0;
    REQUIRE(!CheckExtractInsnHexValue("mov eax, 0x1234", value, 5));

    REQUIRE(CheckExtractInsnHexValue("f0x1234", value, 5));
    REQUIRE(value == 0x1234);

    REQUIRE(CheckExtractInsnHexValue("x1234", value, 5));
    REQUIRE(value == 1234);

    REQUIRE(!CheckExtractInsnHexValue("x", value, 5));

    REQUIRE(CheckExtractInsnHexValue("123", value, 5));
    REQUIRE(value == 123);

    REQUIRE(CheckExtractInsnHexValue("0x123", value, 5));
    REQUIRE(value == 0x123);

    REQUIRE(CheckExtractInsnHexValue("0", value, 5));
    REQUIRE(value == 0);

    REQUIRE(CheckExtractInsnHexValue("0x0", value, 5));
    REQUIRE(value == 0);

    REQUIRE(CheckExtractInsnHexValue("  123", value, 5));
    REQUIRE(value == 123);

    REQUIRE(CheckExtractInsnHexValue("mov ptr [0x123]", value, 5));
    REQUIRE(value == 0x123);

    REQUIRE(!CheckExtractInsnHexValue("mov eax, [0x123]", value, 5));
    REQUIRE(!CheckExtractInsnHexValue("mov [rbp + 0x123]", value, 5));
    REQUIRE(!CheckExtractInsnHexValue("mov [0x123], eax", value, 5));
}

TEST_CASE("AddAndCollapseCollapsibleZones", "[Dissasm]")
{
    DissasmTestInstance dissasmInstance;

    uint32 zoneEndingIndex = 4572;

     REQUIRE(dissasmInstance.CheckLineMnemonic(6, "jmp"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(0, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(1, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(2, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(3, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(4, "int3"));

     REQUIRE(dissasmInstance.AddCollpasibleZone(2, 5));
     REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2 }, { 2, 5, true }, { 5, zoneEndingIndex } }));
     REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 2 }, { 2, 0, 5 } }));

     REQUIRE(!dissasmInstance.AddCollpasibleZone(2, 5));
     REQUIRE(!dissasmInstance.AddCollpasibleZone(1, 4));

     REQUIRE(dissasmInstance.AddCollpasibleZone(0, 2));
     REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, zoneEndingIndex } }));

     REQUIRE(dissasmInstance.AddCollpasibleZone(5, 11));
     REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, 11, true }, { 11, zoneEndingIndex } }));
     REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 2 }, { 2, 0, 5 }, { 3, 3, 8 } }));

     REQUIRE(dissasmInstance.AddCollpasibleZone(7, 9));
     REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, 11, true }, { 11, zoneEndingIndex } }));
     REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 2 }, { 2, 0, 5 }, { 3, 3, 8 } }));
     REQUIRE(dissasmInstance.CheckInternalTypes(2, { { 5, 7 }, { 7, 9, true }, { 9, 11 } }));
     REQUIRE(dissasmInstance.CheckBeforeLinesData(2, { { 0, 0, 5 }, { 1, 1, 6 }, { 2, 2, 7 } }));

     REQUIRE(dissasmInstance.CheckLinesWorkingIndexesSameAsZones());

     REQUIRE(dissasmInstance.CheckLineMnemonic(0, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(1, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(2, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(0, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(6, "jmp"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(3, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(0, "int3"));
     REQUIRE(dissasmInstance.CheckLineMnemonic(4, "int3"));

     REQUIRE(dissasmInstance.CheckCollapseOrExtendZone(8, DissasmCodeZone::CollapseExpandType::Collapse));
     REQUIRE(dissasmInstance.CheckInternalTypes(2, { { 5, 7 }, { 7, 8, true }, { 8, 10 } }));
     REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 2, true }, { 2, 5, true }, { 5, 10, true }, { 10, zoneEndingIndex - 1 } }));
     REQUIRE(!dissasmInstance.CheckCollapseOrExtendZone(7, DissasmCodeZone::CollapseExpandType::Collapse));
     REQUIRE(!dissasmInstance.CheckCollapseOrExtendZone(8, DissasmCodeZone::CollapseExpandType::Collapse));
     REQUIRE(dissasmInstance.CheckCollapseOrExtendZone(1, DissasmCodeZone::CollapseExpandType::Collapse));
     REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 1, true }, { 1, 4, true }, { 4, 9, true }, { 9, zoneEndingIndex - 2 } }));
}

TEST_CASE("AddAndCollapseCollapsibleZones2", "[Dissasm]")
{
    DissasmTestInstance dissasmInstance;

    uint32 zoneEndingIndex = 4572;

    std::array<const char*, 47> mnemonicArrayStart = { "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "sub_0x000000405",
                                                       "jmp",  "EntryPoint",
                                                       "jmp",  "sub_0x00000040F",
                                                       "jmp",  "jmp",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "int3",
                                                       "int3", "sub_0x000000430",
                                                       "push", "mov",
                                                       "sub",  "push",
                                                       "push", "push",
                                                       "mov",  "call",
                                                       "cmp",  "jle",
                                                       "cmp" };
    REQUIRE(dissasmInstance.CheckLineMnemonicArray(0, mnemonicArrayStart.size(), mnemonicArrayStart.data()));
    REQUIRE(dissasmInstance.AddCollpasibleZone(0, 5));
    REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 5, true }, { 5, zoneEndingIndex } }));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 5 } }));
    REQUIRE(dissasmInstance.CheckCollapseOrExtendZone(1, DissasmCodeZone::CollapseExpandType::Collapse));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 5 } }));

    // dissasmInstance.PrintInstructions(50);
    std::array<const char*, 43> mnemonicArrayCollapse1 = { "collapsed", "sub_0x000000405",
                                                           "jmp",       "EntryPoint",
                                                           "jmp",       "sub_0x00000040F",
                                                           "jmp",       "jmp",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "int3",
                                                           "int3",      "sub_0x000000430",
                                                           "push",      "mov",
                                                           "sub",       "push",
                                                           "push",      "push",
                                                           "mov",       "call",
                                                           "cmp",       "jle",
                                                           "cmp" };
    REQUIRE(dissasmInstance.CheckLineMnemonicArray(0, mnemonicArrayCollapse1.size(), mnemonicArrayCollapse1.data()));
    REQUIRE(dissasmInstance.CheckLineOpStr(0, "Zone"));

    REQUIRE(dissasmInstance.AddCollpasibleZone(8, 31));
    REQUIRE(dissasmInstance.CheckBeforeLinesData(-1, { { 0, 0, 0 }, { 1, 0, 5 } }));
    REQUIRE(dissasmInstance.CheckInternalTypes(-1, { { 0, 1, true }, { 1, 8 }, { 8, 31, true }, { 31, zoneEndingIndex } }));
    REQUIRE(dissasmInstance.CheckCollapseOrExtendZone(8, DissasmCodeZone::CollapseExpandType::Collapse));

    std::array<const char*, 21> mnemonicArrayCollapse2 = { "collapsed", "sub_0x000000405",
                                                           "jmp",       "EntryPoint",
                                                           "jmp",       "sub_0x00000040F",
                                                           "jmp",       "jmp",
                                                           "collapsed", "sub_0x000000430",
                                                           "push",      "mov",
                                                           "sub",       "push",
                                                           "push",      "push",
                                                           "mov",       "call",
                                                           "cmp",       "jle",
                                                           "cmp" };
    // dissasmInstance.PrintInstructions(50);
    REQUIRE(dissasmInstance.CheckLineMnemonicArray(0, mnemonicArrayCollapse2.size(), mnemonicArrayCollapse2.data()));
    // dissasmInstance.PrintInstructions(50);
}