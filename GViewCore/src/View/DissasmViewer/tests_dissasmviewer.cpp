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

    bool CheckInternalZones(std::initializer_list<std::pair<uint32, uint32>> zones)
    {
        auto& internalZones = zone->dissasmType.internalTypes;
        if (internalZones.size() != zones.size())
            return false;

        auto it = internalZones.begin();
        for (auto& z : zones) {
            if (it->indexZoneStart != z.first || it->indexZoneEnd != z.second)
                return false;
            ++it;
        }
        return true;
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
    REQUIRE(dissasmInstance.CheckInternalZones({ { 0, 2 }, { 2, 5 }, { 5, 4571 } }));

    REQUIRE(!dissasmInstance.AddCollpasibleZone(2, 5));
    REQUIRE(!dissasmInstance.AddCollpasibleZone(1, 4));

    REQUIRE(dissasmInstance.AddCollpasibleZone(0, 2));
    REQUIRE(dissasmInstance.CheckInternalZones({ { 0, 2 }, { 2, 5 }, { 5, 4571 } }));

    REQUIRE(dissasmInstance.AddCollpasibleZone(5, 11));
    REQUIRE(dissasmInstance.CheckInternalZones({ { 0, 2 }, { 2, 5 }, { 5, 11 }, { 11, 4571 } }));

    REQUIRE(dissasmInstance.AddCollpasibleZone(7, 9));
    REQUIRE(dissasmInstance.CheckInternalZones({ { 0, 2 }, { 2, 5 }, { 5, 7 }, { 7, 9 }, { 9, 11 }, { 11, 4571 } }));

    // TODO: add functionality for this to work
    // REQUIRE(!dissasmInstance.AddCollpasibleZone(1, 3));

    // REQUIRE(dissasmInstance.AddCollpasibleZone(3, 4));

    //// TODO: need joining unnamed regions!
    // REQUIRE(dissasmInstance.CheckInternalZones({ { 0, 2 }, { 2, 3 }, { 3, 4 }, { 4, 5 }, { 5, 4571 } }));

    // REQUIRE(fibonacci(20) == 6'765);
    // BENCHMARK("fibonacci 20")
    //{
    //     return fibonacci(20);
    // };

    // REQUIRE(fibonacci(25) == 75'025);
    // BENCHMARK("fibonacci 25")
    //{
    //     return fibonacci(25);
    // };
}