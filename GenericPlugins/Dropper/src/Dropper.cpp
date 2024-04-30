#include "DropperUI.hpp"

#include <array>
#include <regex>
#include <charconv>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

namespace GView::GenericPlugins::Droppper
{
extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Dropper") {
        auto ui = DropperUI(object);

        switch (ui.Show()) {
        case Dialogs::Result::Ok:
        case Dialogs::Result::Cancel:
            break;
        case Dialogs::Result::None:
        case Dialogs::Result::Yes:
        case Dialogs::Result::No:
        default:
            Dialogs::MessageBox::ShowError("Dropper", "Operation not recognized!");
            break;
        }

        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["command.Dropper"] = Input::Key::F10;
}
}

Instance::~Instance()
{
    UnInitLogs();
}

bool Instance::Init(Reference<GView::Object> object)
{
    CHECK(object.IsValid(), false, "");
    this->object = object;

    if (!context.initialized) {
        // binary
        context.objectDroppers.emplace_back(std::make_unique<MZPE>());
        context.objectDroppers.emplace_back(std::make_unique<PNG>());

        // html objects
        context.objectDroppers.emplace_back(std::make_unique<IFrame>());
        context.objectDroppers.emplace_back(std::make_unique<Script>());
        context.objectDroppers.emplace_back(std::make_unique<XML>());

        bool isCaseSensitive = true;
        bool useUnicode      = true;

        // strings
        context.objectDroppers.emplace_back(std::make_unique<IpAddress>(isCaseSensitive, useUnicode));
        context.objectDroppers.emplace_back(std::make_unique<EmailAddress>(isCaseSensitive, useUnicode));
        context.objectDroppers.emplace_back(std::make_unique<URL>(isCaseSensitive, useUnicode));
        context.objectDroppers.emplace_back(std::make_unique<Registry>(isCaseSensitive, useUnicode));
        context.objectDroppers.emplace_back(std::make_unique<Wallet>(isCaseSensitive, useUnicode));
        context.objectDroppers.emplace_back(std::make_unique<Filepath>(isCaseSensitive, useUnicode));

        // text
        context.textDropper.reset(new Text(isCaseSensitive, useUnicode));
    }

    CHECK(HandleComputationAreas(), false, "");

    return true;
}

void Instance::UnInitLogs()
{
    logFile.close();

    for (auto& [_, f] : singleFiles) {
        f->close();
    }

    singleFiles.clear();
}

BufferView Instance::GetPrecachedBuffer(uint64 offset, DataCache& cache)
{
    return cache.Get(offset, MAX_PRECACHED_BUFFER_SIZE, true);
}

bool Instance::InitLogFile(const std::vector<std::pair<uint64, uint64>>& areas)
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

bool Instance::WriteSummaryToLog(std::map<std::string_view, uint32>& occurences)
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

bool Instance::WriteToLog(uint64 start, uint64 end, Result result, std::unique_ptr<IDrop>& dropper)
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

bool Instance::WriteToFile(uint64 start, uint64 end, std::unique_ptr<IDrop>& dropper, Result result)
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

bool Instance::Process()
{
    CHECK(object.IsValid(), false, "");

    CHECK(InitLogFile(areas), false, "");

    DataCache& cache = object->GetData();
    if (this->computeForFile) {
        CHECK(ProcessObjects(1, cache.GetSize()), false, "");
    } else {
        for (const auto& zone : selectedZones) {
            CHECK(ProcessObjects(zone.start, zone.end), false, "");
        }
    }

    UnInitLogs();

    return true;
}

bool Instance::ProcessObjects(uint64 offset, uint64 size)
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

            for (auto& dropper : context.objectDroppers) {
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
                    nextOffset = end;

                    // adjust for zones
                    if (result == Result::Unicode) {
                        end -= 2;
                    } else if (result == Result::Ascii) {
                        end -= 1;
                    } else {
                        end += 1;
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
        for (auto& dropper : context.objectDroppers) {
            if (dropper->GetName() == f.dropperName) {
                CHECK(WriteToLog(f.start, f.end, f.result, dropper), false, "");
                CHECK(WriteToFile(f.start, f.end, dropper, f.result), false, "");
                break;
            }
        }
    }

    CHECK(ToggleHighlighting(true, zones), false, "");

    return true;
}

bool Instance::ToggleHighlighting(bool value, GView::Utils::ZonesList& zones)
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

bool Instance::HandleComputationAreas()
{
    CHECK(object.IsValid(), false, "");

    this->areas.clear();
    this->selectedZones.clear();

    for (auto i = 0U; i < object->GetContentType()->GetSelectionZonesCount(); i++) {
        const auto zone = object->GetContentType()->GetSelectionZone(i);
        selectedZones.emplace_back(zone);
        areas.push_back({ zone.start, zone.end });
    }
    this->computeForFile = selectedZones.empty();

    DataCache& cache = object->GetData();
    if (computeForFile) {
        areas.push_back({ 0, cache.GetSize() });
    }

    return true;
}

bool Instance::IsComputingFile() const
{
    return this->computeForFile;
}

bool Instance::SetComputingFile(bool value)
{
    this->computeForFile = value;

    if (value) {
        this->areas.clear();
        this->selectedZones.clear();
        areas.push_back({ 0, this->object->GetData().GetSize() });
    } else {
        CHECK(HandleComputationAreas(), false, "");
    }

    return true;
}

bool Instance::DropBinaryData(
      std::string_view filename,
      bool overwriteFile,
      bool openFile,
      std::string_view includedCharSet,
      std::string_view excludedCharSet,
      Reference<Window> parentWindow)
{
    CHECK(ProcessBinaryDataCharset(includedCharSet, excludedCharSet), false, "");

    std::u16string_view fp = object->GetPath();

    LocalUnicodeStringBuilder<4096> lusb;
    CHECK(lusb.Add(object->GetPath()), false, "");

    auto fullPath = static_cast<std::filesystem::path>(lusb).parent_path();
    fullPath /= filename;

    std::ofstream droppedFile;
    const auto flags = overwriteFile ? std::ios::binary : std::ios::binary | std::ios::app;
    droppedFile.open(fullPath, flags);

    CHECK(droppedFile.is_open(), false, "");

    struct Defer {
        std::ofstream& o;
        ~Defer()
        {
            o.close();
        }
    } _{ .o = droppedFile };

    auto& cache          = this->object->GetData();
    const auto cacheSize = cache.GetCacheSize();

    for (const auto& area : areas) {
        const auto size = area.second - area.first;
        if (size < cacheSize) {
            auto bf = cache.Get(area.first, static_cast<int32>(size), true);
            CHECK(bf.IsValid(), false, "");

            for (int32 i = 0; i < bf.GetLength(); i++) {
                const auto c = bf[i];
                if (context.textMatrix[c]) {
                    droppedFile << c;
                }
            }
        } else {
            auto sizeLeft = size - cacheSize;
            auto offset   = area.first;
            auto bf       = cache.Get(offset, cacheSize, true);
            offset += cacheSize;

            while (bf.IsValid() && !bf.Empty()) {
                for (int32 i = 0; i < bf.GetLength(); i++) {
                    const auto c = bf[i];
                    if (context.textMatrix[c]) {
                        droppedFile << c;
                    }
                }

                const auto sizeToRead = std::min<int64>(sizeLeft, cacheSize);
                sizeLeft -= sizeToRead;

                bf = cache.Get(offset, static_cast<int32>(sizeToRead), true);
                offset += sizeToRead;
            }
        }
    }

    CHECK(droppedFile.good(), false, "");

    if (openFile) {
        GView::App::OpenFile(fullPath, GView::App::OpenMethod::BestMatch, "", parentWindow);
    }

    return true;
}

static std::optional<int32> HexToByte(std::string_view s)
{
    CHECK(s.size() == 2, std::nullopt, "");

    char nibbles[2]{ 0 };
    for (int32 i = 0; i < 2; i++) {
        if ((s[i] >= '0') && (s[i] <= '9')) {
            nibbles[i] = s[i] - '0';
        } else if ((s[i] >= 'A') && (s[i] <= 'F')) {
            nibbles[i] = (s[i] - 'A') + 10;
        } else if ((s[i] >= 'a') && (s[i] <= 'f')) {
            nibbles[i] = (s[i] - 'a') + 10;
        } else {
            return std::nullopt;
        }
    }

    return (nibbles[0] << 4) | nibbles[1];
}

bool Instance::ProcessBinaryDataCharset(std::string_view include, std::string_view exclude)
{
    if (include == DEFAULT_INCLUDE_CHARSET && exclude == DEFAULT_EXCLUDE_CHARSET) {
        memset(context.textMatrix, true, CHARSET_MATRIX_SIZE);
        return true;
    }

    memset(context.textMatrix, false, CHARSET_MATRIX_SIZE);

    const auto ValidateHex = [](std::string_view s) -> bool {
        CHECK(s[0] == '\\', false, "");
        CHECK(s[1] == 'x', false, "");
        CHECK(s[2] >= '0' && s[2] <= '9' || s[2] >= 'a' && s[2] <= 'z' || s[2] >= 'A' && s[2] <= 'Z', false, "");
        CHECK(s[3] >= '0' && s[3] <= '9' || s[3] >= 'a' && s[3] <= 'z' || s[3] >= 'A' && s[3] <= 'Z', false, "");
        return true;
    };

    const auto FillMatrix = [ValidateHex](std::string_view s, bool value) -> bool {
        const auto includeSize = static_cast<int32>(s.size());
        for (int32 i = 0; i < includeSize; i++) {
            switch (s[i]) {
            case '\\': {
                const auto delta = includeSize - i;
                CHECK(delta >= HEX_NUMBER_SIZE, false, "");

                CHECK(ValidateHex(std::string_view{ s.data() + i, HEX_NUMBER_SIZE }), false, "");
                const auto v1 = HexToByte(std::string_view{ s.data() + i + 2, HEX_NUMBER_SIZE - 2 });
                CHECK(v1.has_value(), false, "");

                std::optional<int32> v2 = v1;

                i = static_cast<int32>(i + HEX_NUMBER_SIZE);

                if (delta > HEX_NUMBER_SIZE) {
                    auto sep = s[i];

                    if (sep == ',') {
                        // nothing
                    } else if (sep == '-') {
                        CHECK(ValidateHex(std::string_view{ s.data() + i + 1, HEX_NUMBER_SIZE }), false, "");
                        v2 = HexToByte(std::string_view{ s.data() + i + 1 + 2, HEX_NUMBER_SIZE - 2 });
                        CHECK(v2.has_value(), false, "");
                        CHECK(*v1 <= *v2, false, "");
                        i = static_cast<int32>(i + HEX_NUMBER_SIZE + 1ULL);
                    } else {
                        return false;
                    }
                }

                memset(context.textMatrix + *v1, value, static_cast<uint64>(*v2) - *v1 + 1);
            } break;
            default: {
                const auto v1 = s[i] - '0';
                auto v2       = v1;

                if (i < includeSize - 1) {
                    const auto sep = s[i + 1ULL];

                    if (sep == ',') {
                        i = static_cast<int32>(i + 1ULL);
                    } else if (sep == '-') {
                        v2 = s[i + 2ULL];
                        CHECK(v1 <= v2, false, "");
                        i = static_cast<int32>(i + 2ULL);
                    } else {
                        return false;
                    }
                }

                memset(context.textMatrix + v1, value, static_cast<uint64>(v2) - v1 + 1);
            } break;
            }
        }

        return true;
    };

    CHECK(FillMatrix(include, true), false, "");
    CHECK(FillMatrix(exclude, false), false, "");

    return true;
}
} // namespace GView::GenericPlugins::Droppper
