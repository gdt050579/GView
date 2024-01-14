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

    DissasmTestInstance()
    {
        instance = nullptr;
        // Settings settings = {};
        // DummyType dummyType;
        // GView::Utils::DataCache cache = GView::Utils::DataCache();
        // GView::Object obj             = GView::Object(GView::Object::Type::MemoryBuffer, std::move(cache), &dummyType, "dummy", "loc", 1);
        // instance                      = new Instance(&obj, &settings);
    }

    std::unique_ptr<DissasmCodeZone> initDissasmCodeZone(Reference<GView::Object> obj)
    {
        std::unique_ptr<DissasmCodeZone> zone = std::make_unique<DissasmCodeZone>();
        zone->dissasmType                     = {};
        zone->dissasmType.indexZoneStart      = 0;
        zone->dissasmType.indexZoneEnd        = 4800;

        zone->zoneDetails.startingZonePoint = 1024;
        zone->zoneDetails.size              = 5120;
        zone->zoneDetails.entryPoint        = 1034;

        zone->internalArchitecture = 4;
        zone->isInit               = true;

        zone->types.push_back(zone->dissasmType);
        zone->levels.push_back(0);

        zone->dissasmType.annotations[5]   = { "sub_0x000000405", 5 };
        zone->dissasmType.annotations[7]   = { "EntryPoint", 10 };
        zone->dissasmType.annotations[34]  = { "sub_0x000000430", 48 };
        zone->dissasmType.annotations[47]  = { "offset_0x00000044F", 79 };
        zone->dissasmType.annotations[50]  = { "offset_0x000000457", 87 };
        zone->dissasmType.annotations[111] = { "offset_0x000000545", 325 };
        zone->dissasmType.annotations[113] = { "offset_0x000000548", 328 };
        zone->dissasmType.annotations[144] = { "offset_0x00000058E", 398 };
        zone->dissasmType.annotations[341] = { "sub_0x0000006A0", 672 };
        zone->dissasmType.annotations[357] = { "sub_0x0000006B0", 688 };
        zone->dissasmType.annotations[415] = { "sub_0x000000720", 800 };
        zone->dissasmType.annotations[432] = { "offset_0x000000751", 849 };

        zone->cachedCodeOffsets.push_back({ 1024, 0 });
        zone->cachedCodeOffsets.push_back({ 1524, 181 });
        zone->cachedCodeOffsets.push_back({ 2024, 566 });
        zone->cachedCodeOffsets.push_back({ 2524, 1066 });
        zone->cachedCodeOffsets.push_back({ 3024, 1566 });
        zone->cachedCodeOffsets.push_back({ 3524, 2066 });
        zone->cachedCodeOffsets.push_back({ 4024, 2566 });
        zone->cachedCodeOffsets.push_back({ 4524, 3066 });
        zone->cachedCodeOffsets.push_back({ 5024, 3566 });
        zone->cachedCodeOffsets.push_back({ 5524, 4066 });
        zone->cachedCodeOffsets.push_back({ 6025, 4562 });

        zone->lastDrawnLine   = 0;
        zone->lastClosestLine = 0;
        zone->isInit          = true;

        zone->asmAddress = 0;
        zone->asmSize    = zone->zoneDetails.size - zone->asmAddress;

        const auto instructionData = obj->GetData().Get(zone->cachedCodeOffsets[0].offset + zone->asmAddress, static_cast<uint32>(zone->asmSize), false);
        zone->lastData             = instructionData;
        if (!instructionData.IsValid()) {
            printf("ERROR: extract valid data from file!");
            assert(false);
        }
        zone->asmData = const_cast<uint8*>(instructionData.GetData());

        return zone;
    }

    bool check_DissasmAddCollpasibleZone()
    {
        // TODO: add checks
        auto buffer                   = AppCUI::OS::File::ReadContent(R"(D:\todo\my_examples\s3\ConsoleApplication5.exeda.data)");
        GView::Utils::DataCache cache = GView::Utils::DataCache();

        std::unique_ptr<AppCUI::OS::File> f = std::make_unique<AppCUI::OS::File>();
        // TODO: add data statically ?
        f->OpenRead(R"(D:\todo\my_examples\s3\ConsoleApplication5.exeda.data)");

        cache.Init(std::move(f), buffer.GetLength());

        GView::Object obj = GView::Object(GView::Object::Type::MemoryBuffer, std::move(cache), nullptr, "dummy", "loc", 1);
        auto zone         = initDissasmCodeZone(&obj);

        zone->AddCollapsibleZone(&obj, 2, 5);
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

    REQUIRE(dissasmInstance.check_DissasmAddCollpasibleZone());

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
