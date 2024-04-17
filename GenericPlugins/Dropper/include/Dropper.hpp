#pragma once

#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

#include "SpecialStrings.hpp"
#include "Executables.hpp"
#include "Multimedia.hpp"
#include "HtmlObjects.hpp"

using namespace GView::Utils;
using namespace GView::GenericPlugins::Droppper::SpecialStrings;
using namespace GView::GenericPlugins::Droppper::Executables;
using namespace GView::GenericPlugins::Droppper::Multimedia;
using namespace GView::GenericPlugins::Droppper::HtmlObjects;

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

    std::map<std::string_view, std::unique_ptr<std::ofstream>> singleFiles;

    inline static constexpr uint32 SEPARATOR_LENGTH = 80;

  public:
    Instance()
    {
        if (!context.initialized) {
            // binary
            context.droppers.emplace_back(std::make_unique<MZPE>());
            context.droppers.emplace_back(std::make_unique<PNG>());

            // html objects
            context.droppers.emplace_back(std::make_unique<IFrame>());
            context.droppers.emplace_back(std::make_unique<Script>());
            context.droppers.emplace_back(std::make_unique<XML>());

            bool isCaseSensitive = true;
            bool useUnicode      = true;

            // strings
            context.droppers.emplace_back(std::make_unique<IpAddress>(isCaseSensitive, useUnicode));
            context.droppers.emplace_back(std::make_unique<EmailAddress>(isCaseSensitive, useUnicode));
            context.droppers.emplace_back(std::make_unique<URL>(isCaseSensitive, useUnicode));
            context.droppers.emplace_back(std::make_unique<Registry>(isCaseSensitive, useUnicode));
            context.droppers.emplace_back(std::make_unique<Wallet>(isCaseSensitive, useUnicode));
            context.droppers.emplace_back(std::make_unique<Filepath>(isCaseSensitive, useUnicode));
            context.droppers.emplace_back(std::make_unique<Text>(isCaseSensitive, useUnicode));
        }
    }

    ~Instance()
    {
        logFile.close();

        for (auto& [_, f] : singleFiles) {
            f->close();
        }
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
        stream << std::setfill('-') << std::setw(SEPARATOR_LENGTH) << '-' << std::endl;

        logFile << stream.str();
        CHECK(logFile.good(), false, "");

        return true;
    }

    bool WriteSummaryToLog(std::map<std::string_view, uint32>& occurences)
    {
        CHECK(logFile.is_open(), false, "");

        std::ostringstream stream;
        for (const auto& [k, v] : occurences) {
            stream << std::setfill(' ') << std::left << std::setw(16) << k << ": " << std::right << std::setw(16) << std::dec << v << std::endl;
        }
        stream << std::setfill('-') << std::setw(SEPARATOR_LENGTH) << '-' << std::endl;

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
        stream << std::setfill(' ') << std::setw(16) << dropper->GetName() << "] [";
        stream << std::setfill(' ') << std::setw(8) << RESULT_MAP.at(result) << "] [";
        stream << std::setfill(' ') << std::setw(16) << OBJECT_CATEGORY_MAP.at(dropper->GetGroup()) << "]" << std::endl;

        logFile << stream.str();
        CHECK(logFile.good(), false, "");

        return true;
    }

    bool WriteToFile(Reference<GView::Object> object, uint64 start, uint64 end, std::unique_ptr<IDrop>& dropper, Result result)
    {
        auto bv = object->GetData().Get(start, static_cast<uint32>(end - start), true);
        CHECK(bv.IsValid(), false, "");

        LocalUnicodeStringBuilder<4096> filename;

        std::string_view name = dropper->GetName();
        if (dropper->ShouldGroupInOneFile()) {
            if (!singleFiles.contains(name)) {
                filename.Add(object->GetPath());
                filename.Add(".");
                filename.Add(dropper->GetOutputExtension());

                std::string filenameUTF8;
                filename.ToString(filenameUTF8);

                auto f = std::make_unique<std::ofstream>();
                f->open(filenameUTF8, std::ios::out | std::ios::app | std::ios::binary);
                CHECK(f->is_open(), false, "");

                std::filesystem::resize_file(filenameUTF8, 0);
                f->seekp(0);

                singleFiles[name] = std::move(f);
            }

            auto& f = singleFiles.at(name);

            if (result != Result::Unicode) {
                f->write(reinterpret_cast<const char*>(bv.GetData()), bv.GetLength());
            } else {
                for (uint32 i = 0; i < bv.GetLength(); i += 2) {
                    f->write(reinterpret_cast<const char*>(bv.GetData() + i), 1);
                }
            }
            f->write("\n", 1);
        } else {
            filename.Add(object->GetPath());
            filename.Add(".obj.");
            filename.Add(std::to_string(objectId++));
            filename.Add(".");
            filename.Add(dropper->GetOutputExtension());

            std::string filenameUTF8;
            filename.ToString(filenameUTF8);

            std::ofstream f;
            f.open(filenameUTF8, std::ios::out | std::ios::binary);
            CHECK(f.is_open(), false, "");
            f.write(reinterpret_cast<const char*>(bv.GetData()), bv.GetLength());
            f.close();
        }

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
        struct Data {
            uint64 start;
            uint64 end;
            Result result;
            std::string_view dropperName;
        };

        std::vector<Data> findings;
        std::map<std::string_view, uint32> occurences;
        GView::Utils::ZonesList zones;

        DataCache& cache  = object->GetData();
        uint64 nextOffset = offset;

        ProgressStatus::Init("Searching...", size);
        LocalString<512> ls;
        const char* format          = "[%llu/%llu] bytes... Found [%u] objects.";
        constexpr uint64 CHUNK_SIZE = 10000;
        uint64 chunks               = offset / CHUNK_SIZE;
        uint64 toUpdate             = chunks * CHUNK_SIZE;
        while (offset < size) {
            if (offset >= toUpdate) {
                uint32 objectsCount = 0;
                for (const auto& [_, v] : occurences) {
                    objectsCount += v;
                }

                CHECKBK(ProgressStatus::Update(offset, ls.Format(format, offset, size, objectsCount)) == false, "");
                chunks += 1;
                toUpdate = chunks * CHUNK_SIZE;

                cache.Get(offset, cache.GetCacheSize(), false); // optimization
            }

            auto buffer = GetPrecachedBuffer(offset, cache);
            CHECKBK(buffer.GetLength() > 0, "");
            nextOffset = offset + 1;

            for (uint32 i = 0; i < static_cast<uint32>(Priority::Count); i++) {
                const auto priority = static_cast<Priority>(i);
                if (priority == Priority::Text) {
                    if (!IDrop::IsAsciiPrintable(buffer.GetData()[0])) {
                        continue;
                    }
                }

                for (auto& dropper : context.droppers) {
                    if (dropper->GetPriority() != priority) {
                        continue;
                    }

                    uint64 start      = 0;
                    uint64 end        = 0;
                    const auto result = dropper->Check(offset, cache, buffer, start, end);

                    if (result != Result::NotFound) {
                        const auto name = dropper->GetName();
                        occurences[name] += 1;
                        findings.push_back({ start, end, result, name });
                        nextOffset = end + 1;

                        // adjust for zones
                        if (result == Result::Unicode) {
                            end -= 2;
                        } else if (result == Result::Ascii) {
                            end -= 1;
                        }
                        zones.Add(start, end, OBJECT_CATEGORY_COLOR_MAP.at(dropper->GetGroup()), dropper->GetName());

                        break;
                    }
                }
            }

            offset = nextOffset;
        }

        uint32 objectsCount = 0;
        for (const auto& [_, v] : occurences) {
            objectsCount += v;
        }
        ProgressStatus::Update(size, ls.Format(format, size, size, objectsCount));

        WriteSummaryToLog(occurences);
        for (const auto& f : findings) {
            for (auto& dropper : context.droppers) {
                if (dropper->GetName() == f.dropperName) {
                    CHECK(WriteToLog(f.start, f.end, f.result, dropper), false, "");
                    CHECK(WriteToFile(object, f.start, f.end, dropper, f.result), false, "");
                    break;
                }
            }
        }

        CHECK(ToggleSync(true, zones), false, "");

        return true;
    }

    bool ToggleSync(bool value, GView::Utils::ZonesList& zones)
    {
        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++) {
            auto window    = desktop->GetChild(i);
            auto interface = window.ToObjectRef<GView::View::WindowInterface>();
            auto view      = interface->GetCurrentView();

            if (value) {
                CHECK(view->SetObjectsHighlightingZonesList(zones), false, "");
            }
            CHECK(view->OnEvent(
                        nullptr,
                        AppCUI::Controls::Event::Command,
                        value ? View::VIEW_COMMAND_ACTIVATE_OBJECT_HIGHLIGHTING : View::VIEW_COMMAND_DEACTIVATE_OBJECT_HIGHLIGHTING),
                  false,
                  "");
        }

        return true;
    }
};
} // namespace GView::GenericPlugins::Droppper
