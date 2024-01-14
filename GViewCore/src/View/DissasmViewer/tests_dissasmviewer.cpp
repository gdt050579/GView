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
        //CHECK(selectionZoneInterface.IsValid(), 0, "");
        return selectionZoneInterface->GetSelectionZonesCount();
    }

    TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
    {
        static auto d = TypeInterface::SelectionZone{ 0, 0 };
        //CHECK(selectionZoneInterface.IsValid(), d, "");
        //CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

        return selectionZoneInterface->GetSelectionZone(index);
    }
};

class DissasmTestInstance
{
  public:
    Instance* instance;

    DissasmTestInstance()
    {
        Settings settings = {};

        DummyType dummyType;
        GView::Utils::DataCache cache = GView::Utils::DataCache();
        GView::Object obj             = GView::Object(GView::Object::Type::MemoryBuffer, std::move(cache), &dummyType, "dummy", "loc", 1);
        instance                      = new Instance(&obj, &settings);
    }

    DissasmCodeZone initDissasmCodeZone()
    {
        DissasmCodeZone zone = {};
        zone.dissasmType     = {};
        zone.dissasmType.indexZoneStart = 0;
        zone.dissasmType.indexZoneEnd = 100;
        zone.dissasmType.annotations[2] = { "line2", 2 };
        zone.dissasmType.annotations[5] = { "line5", 5 };
        zone.dissasmType.annotations[9] = { "line9", 9 };
        return zone;
    }

    bool check_DissasmAddCollpasibleZone()
    {
        auto zone = initDissasmCodeZone();
        instance->DissasmAddCollpasibleZone(&zone,2,5);
        return true;
    }

    ~DissasmTestInstance()
    {
        delete instance;
    }
};

TEST_CASE("Benchmark DissasmView", "[!benchmark]")
{
    DissasmTestInstance dissasmInstance;

    REQUIRE(dissasmInstance.check_DissasmAddCollpasibleZone());

    //REQUIRE(fibonacci(20) == 6'765);
    //BENCHMARK("fibonacci 20")
    //{
    //    return fibonacci(20);
    //};

    //REQUIRE(fibonacci(25) == 75'025);
    //BENCHMARK("fibonacci 25")
    //{
    //    return fibonacci(25);
    //};
}
