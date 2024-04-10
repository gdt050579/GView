#pragma once

#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "SpecialStrings.hpp"
#include "Executables.hpp"
#include "Multimedia.hpp"

using namespace GView::Utils;
using namespace GView::GenericPlugins::Droppper::SpecialStrings;
using namespace GView::GenericPlugins::Droppper::Executables;
using namespace GView::GenericPlugins::Droppper::Multimedia;

namespace GView::GenericPlugins::Droppper
{
class Instance
{
  private:
    inline static struct Context {
        std::vector<std::unique_ptr<IDrop>> droppers;
        bool initialized{ false };
    } context;

    std::ofstream logFile;
    uint64 objectId{ 0 };

  public:
    Instance()
    {
        if (!context.initialized) {
            context.droppers.emplace_back(std::make_unique<IpAddress>(false, true));
            context.droppers.emplace_back(std::make_unique<MZPE>());
            context.droppers.emplace_back(std::make_unique<PNG>());
        }
    }

    ~Instance()
    {
        logFile.close();
    }

    BufferView GetPrecachedBuffer(uint64 offset, DataCache& cache)
    {
        return cache.Get(offset, MAX_PRECACHED_BUFFER_SIZE, true);
    }

    bool InitLogFile(Reference<GView::Object> object, const std::vector<std::pair<uint64, uint64>>& areas)
    {
        LocalUnicodeStringBuilder<4096> logFilename;
        logFilename.Add(object->GetPath());
        logFilename.Add(".dropper.log");

        std::string logFilenameUTF8;
        logFilename.ToString(logFilenameUTF8);

        logFile.open(logFilenameUTF8, std::ios::out);

        CHECK(logFile.is_open(), false, "");

        std::ostringstream stream;

        for (const auto& area : areas) {
            stream << "Start Address: " << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << area.first << std::endl;
            stream << "End Address  : " << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << area.second << std::endl;
        }
        stream << std::setfill('-') << std::setw(59) << '-' << std::endl;

        logFile << stream.str();
        CHECK(logFile.good(), false, "");

        return true;
    }

    bool WriteToLog(uint64 start, uint64 end, Result result, std::unique_ptr<IDrop>& dropper)
    {
        CHECK(logFile.is_open(), false, "");

        std::ostringstream stream;
        stream << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << start << ": ";
        stream << std::setfill(' ') << std::setw(8) << std::dec << (end - start) << " bytes -> [";
        stream << std::setfill(' ') << std::setw(8) << dropper->GetName() << "] ";
        stream << std::setfill(' ') << std::setw(8) << RESULT_MAP.at(result) << " ";
        stream << std::setfill(' ') << std::setw(8) << OBJECT_CATEGORY_MAP.at(dropper->GetGroup()) << std::endl;

        logFile << stream.str();
        CHECK(logFile.good(), false, "");

        return true;
    }

    bool Process(Reference<GView::Object> object)
    {
        CHECK(object.IsValid(), false, "");

        std::vector<std::pair<uint64, uint64>> areas;

        std::vector<GView::TypeInterface::SelectionZone> selectedZones;
        for (auto i = 0U; i < object->GetContentType()->GetSelectionZonesCount(); i++) {
            const auto zone = object->GetContentType()->GetSelectionZone(i);
            selectedZones.emplace_back(zone);
            areas.push_back({ zone.start, zone.end });
        }
        const auto computeForFile = selectedZones.empty();

        DataCache& cache = object->GetData();
        if (computeForFile) {
            areas.push_back({ 0, cache.GetSize() });
        }

        CHECK(InitLogFile(object, areas), false, "");

        if (computeForFile) {
            CHECK(__Process(object, 1, cache.GetSize()), false, "");
        } else {
            for (const auto& zone : selectedZones) {
                CHECK(__Process(object, zone.start, zone.end), false, "");
            }
        }

        return true;
    }

    bool __Process(Reference<GView::Object> object, uint64 offset, uint64 size)
    {
        DataCache& cache  = object->GetData();
        uint64 nextOffset = offset;

        while (offset < size) {
            auto buffer = GetPrecachedBuffer(offset, cache);
            nextOffset  = offset + 1;

            for (uint32 i = 0; i < static_cast<uint32>(Priority::Count); i++) {
                const auto priority = static_cast<Priority>(i);
                auto found          = false;
                for (auto& dropper : context.droppers) {
                    if (dropper->GetPriority() != priority) {
                        continue;
                    }

                    uint64 start      = 0;
                    uint64 end        = 0;
                    const auto result = dropper->Check(offset, cache, buffer, start, end);
                    found             = result != Result::NotFound;

                    switch (result) {
                    case Result::Buffer:
                        CHECK(WriteToLog(start, end, result, dropper), false, "");
                        nextOffset = end + 1;
                        break;
                    case Result::Ascii:
                        CHECK(WriteToLog(start, end, result, dropper), false, "");
                        nextOffset = end + 1;
                        break;
                    case Result::Unicode:
                        CHECK(WriteToLog(start, end, result, dropper), false, "");
                        nextOffset = end + 1;
                        break;
                    case Result::NotFound:
                    default:
                        break;
                    }

                    if (found) {
                        break;
                    }
                }
            }

            offset = nextOffset;
        }

        return true;
    }
};
} // namespace GView::GenericPlugins::Droppper
