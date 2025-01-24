#include "DropperUI.hpp"

#include "Artefacts.hpp"

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
    sect["Command.Dropper"] = Input::Key::F10;
}
}

bool Instance::Init(Reference<GView::Object> object)
{
    CHECK(object.IsValid(), false, "");
    this->object = object;

    if (!context.initialized) {
        // binary
        context.objectDroppers.emplace_back(std::make_unique<MZPE>());
        context.objectDroppers.emplace_back(std::make_unique<PNG>());
        context.objectDroppers.emplace_back(std::make_unique<JPG>());

        // html objects
        context.objectDroppers.emplace_back(std::make_unique<IFrame>());
        context.objectDroppers.emplace_back(std::make_unique<PHP>());
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

        context.initialized = true;
    }

    CHECK(HandleComputationAreas(), false, "");

    return true;
}

BufferView Instance::GetPrecachedBuffer(uint64 offset, DataCache& cache)
{
    return cache.Get(offset, MAX_PRECACHED_BUFFER_SIZE, true);
}

std::optional<std::ofstream> Instance::InitLogFile(const std::filesystem::path& p, const std::vector<std::pair<uint64, uint64>>& areas, bool noHeader)
{
    std::ofstream logFile;
    logFile.open(p, std::ios::out);
    CHECK(logFile.is_open(), std::nullopt, "");

    if (!noHeader) {
        for (const auto& area : areas) {
            logFile << "Start Address: " << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << area.first << std::endl;
            logFile << "End Address  : " << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << area.second << std::endl;
        }
        logFile << std::setfill('-') << std::setw(SEPARATOR_LENGTH) << '-' << std::endl;
    }

    return logFile;
}

bool Instance::WriteSummaryToLog(std::ofstream& f, std::map<std::string_view, uint32>& occurences)
{
    CHECK(f.is_open(), false, "");

    for (const auto& [k, v] : occurences) {
        f << std::setfill(' ') << std::left << std::setw(16) << k << ": " << std::right << std::setw(16) << std::dec << v << std::endl;
    }
    f << std::setfill('-') << std::setw(SEPARATOR_LENGTH) << '-' << std::endl;

    CHECK(f.good(), false, "");

    return true;
}

bool Instance::WriteToLog(std::ofstream& f, uint64 start, uint64 end, Result result, std::unique_ptr<IDrop>& dropper, bool addValue, bool writeValueOnly)
{
    CHECK(f.is_open(), false, "");

    if (!writeValueOnly) {
        auto& cache = this->object->GetData();
        auto bv     = cache.Get(start, static_cast<uint32>(end - start), false);
        CHECK(bv.IsValid(), false, "");

        f << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << start << ": ";
        f << std::setfill(' ') << std::setw(8) << std::dec << (end - start) << " bytes -> [";
        f << std::setfill(' ') << std::setw(16) << dropper->GetName() << "] [";
        f << std::setfill(' ') << std::setw(8) << RESULT_MAP.at(result) << "] [";
        f << std::setfill(' ') << std::setw(16) << OBJECT_CATEGORY_MAP.at(dropper->GetCategory()) << "]";

        if (addValue) {
            f << ": VALUE -> ";
        }
    }

    if (addValue || writeValueOnly) {
        auto& cache = this->object->GetData();
        auto bv     = cache.Get(start, static_cast<uint32>(end - start), true);
        CHECK(bv.IsValid(), false, "");

        switch (result) {
        case GView::GenericPlugins::Droppper::Result::NotFound:
            break;
        case GView::GenericPlugins::Droppper::Result::Buffer:
            break;
        case GView::GenericPlugins::Droppper::Result::Ascii:
            f.write(reinterpret_cast<const char*>(bv.GetData()), bv.GetLength());
            break;
        case GView::GenericPlugins::Droppper::Result::Unicode:
            for (uint32 i = 0; i < bv.GetLength(); i += 2) {
                f.write(reinterpret_cast<const char*>(bv.GetData() + i), 1);
            }
            break;
        default:
            break;
        }
    }

    f << std::endl;

    CHECK(f.good(), false, "");

    return true;
}

bool Instance::WriteToFile(std::filesystem::path path, uint64 start, uint64 end, std::unique_ptr<IDrop>& dropper, Result result)
{
    auto bv = object->GetData().Get(start, static_cast<uint32>(end - start), false);
    CHECK(bv.IsValid(), false, "");

    auto flags = std::ios::out | std::ios::binary;
    if (dropper->ShouldGroupInOneFile()) {
        std::string f = path.filename().string().append(".").append(dropper->GetOutputExtension());
        path          = path.parent_path() / f;
        flags |= std::ios::app;
    } else {
        std::string f = path.filename().string().append(".obj.").append(std::to_string(objectId++)).append(".").append(dropper->GetOutputExtension());
        path          = path.parent_path() / f;
    }

    std::ofstream f;
    f.open(path, flags);
    CHECK(f.is_open(), false, "");

    if (dropper->ShouldGroupInOneFile()) {
        if (result == Result::Unicode) {
            for (uint32 i = 0; i < bv.GetLength(); i += 2) {
                f.write(reinterpret_cast<const char*>(bv.GetData() + i), 1);
            }
        } else {
            f.write(reinterpret_cast<const char*>(bv.GetData()), bv.GetLength());
        }
        f.write("\n", 1);
    } else {
        f.write(reinterpret_cast<const char*>(bv.GetData()), bv.GetLength());
    }

    f.close();

    context.objectPaths.insert(path);

    return true;
}

bool Instance::DropObjects(
      const std::vector<PluginClassification>& plugins,
      const std::filesystem::path& path,
      const std::filesystem::path& logPath,
      bool recursive,
      bool writeLog,
      bool highlightObjects)
{
    CHECK(context.initialized, false, "");
    CHECK(object.IsValid(), false, "");

    context.zones.Clear();
    context.findings.clear();
    context.occurences.clear();
    context.objectPaths.clear();

    DataCache& cache = object->GetData();
    if (this->computeForFile) {
        CHECK(ProcessObjects(plugins, 1, cache.GetSize(), recursive), false, "");
    } else {
        for (const auto& zone : selectedZones) {
            CHECK(ProcessObjects(plugins, zone.start, zone.end, recursive), false, "");
        }
    }

    if (writeLog) {
        auto logFile = InitLogFile(logPath, areas);
        CHECK(logFile.has_value(), false, "");

        struct Defer {
            std::ofstream& o;
            ~Defer()
            {
                o.close();
            }
        } _{ .o = *logFile };

        CHECK(logFile->good(), false, "");

        WriteSummaryToLog(*logFile, context.occurences);
        for (const auto& f : context.findings) {
            for (auto& dropper : context.objectDroppers) {
                if (dropper->GetName() == f.dropperName) {
                    CHECK(WriteToLog(*logFile, f.start, f.end, f.result, dropper), false, "");
                    CHECK(WriteToFile(path, f.start, f.end, dropper, f.result), false, "");
                    break;
                }
            }
        }
    }

    if (highlightObjects) {
        CHECK(SetHighlighting(true), false, "");
    }

    return true;
}

bool Instance::ProcessObjects(
      const std::vector<PluginClassification>& plugins, uint64 offset, uint64 size, bool recursive, ArtefactIdentificationCallback identify)
{
    DataCache& cache  = object->GetData();
    uint64 nextOffset = offset;

    std::vector<std::unique_ptr<IDrop>*> whitelistedPlugins;
    whitelistedPlugins.reserve(context.objectDroppers.size());
    if (plugins.size() == 1 && context.textDropper->GetCategory() == plugins[0].category && context.textDropper->GetSubcategory() == plugins[0].subcategory) {
        whitelistedPlugins.push_back(&context.textDropper);
    } else {
        for (auto& d : context.objectDroppers) {
            for (const auto& p : plugins) {
                if (d->GetCategory() == p.category && d->GetSubcategory() == p.subcategory) {
                    whitelistedPlugins.push_back(&d);
                    break;
                }
            }
        }
    }
    if (identify != nullptr && plugins.size() > 1) {
        whitelistedPlugins.push_back(&context.textDropper);
    }

    ProgressStatus::Init("Searching...", size);
    LocalString<512> ls;
    const char* format          = "[%llu/%llu] bytes... Found [%u] object(s).";
    constexpr uint64 CHUNK_SIZE = 10000;
    uint64 chunks               = offset / CHUNK_SIZE;
    uint64 toUpdate             = chunks * CHUNK_SIZE;
    while (offset < size) {
        if (offset >= toUpdate) {
            uint32 objectsCount = 0;
            for (const auto& [_, v] : context.occurences) {
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

            for (auto& dropper : whitelistedPlugins) {
                if ((*dropper)->GetPriority() != priority) {
                    continue;
                }

                Finding finding{ .dropperName = (*dropper)->GetName(), .category = (*dropper)->GetCategory(), .subcategory = (*dropper)->GetSubcategory() };
                const auto result = (*dropper)->Check(offset, cache, buffer, finding);

                if (result && finding.result != Result::NotFound) {
                    auto& f = context.findings.emplace_back(finding);
                    context.occurences[f.dropperName] += 1;

                    if (!recursive) {
                        nextOffset = f.end;
                    }

                    // adjust for zones
                    if (f.result == Result::Unicode) {
                        f.end -= 2;
                    } else if (f.result == Result::Ascii) {
                        f.end -= 1;
                    } else {
                        f.end += 1;
                    }
                    context.zones.Add(f.start, f.end, OBJECT_CATEGORY_COLOR_MAP.at(f.category), f.dropperName);

                    if (identify != nullptr) {
                        f.artefact = identify(cache, f.subcategory, f.start, f.end, f.result);
                    }

                    break;
                }
            }
        }

        offset = nextOffset;
    }

    uint32 objectsCount = 0;
    for (const auto& [_, v] : context.occurences) {
        objectsCount += v;
    }
    ProgressStatus::Update(size, ls.Format(format, size, size, objectsCount));

    return true;
}

bool Instance::SetHighlighting(bool value, bool warn)
{
    if (value) {
        if (context.zones.GetCount() == 0) {
            if (warn) {
                Dialogs::MessageBox::ShowWarning("Object Highlighting", "There are no objects to highlight!");
            }
            return true;
        }
    }

    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    for (uint32 i = 0; i < windowsNo; i++) {
        auto window    = desktop->GetChild(i);
        auto interface = window.ToObjectRef<GView::View::WindowInterface>();
        auto view      = interface->GetCurrentView();

        if (value) {
            CHECK(view->SetObjectsHighlightingZonesList(context.zones), false, "");
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

const std::set<std::filesystem::path>& Instance::GetObjectsPaths() const
{
    return context.objectPaths;
}

const std::vector<Finding>& Instance::GetFindings() const
{
    return context.findings;
}

bool Instance::DropBinaryData(
      std::string_view filename,
      bool overwriteFile,
      bool openFile,
      std::string_view includedCharSet,
      std::string_view excludedCharSet,
      Reference<Window> parentWindow)
{
    CHECK(context.initialized, false, "");
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
                if (context.binaryCharSetMatrix[c]) {
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
                    if (context.binaryCharSetMatrix[c]) {
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

bool Instance::FillCharSetMatrix(bool binaryCharSetMatrix[BINARY_CHARSET_MATRIX_SIZE], std::string_view s, bool value)
{
    const auto static ValidateHex = [](std::string_view s) -> bool {
        CHECK(s[0] == '\\', false, "");
        CHECK(s[1] == 'x', false, "");
        CHECK(s[2] >= '0' && s[2] <= '9' || s[2] >= 'a' && s[2] <= 'z' || s[2] >= 'A' && s[2] <= 'Z', false, "");
        CHECK(s[3] >= '0' && s[3] <= '9' || s[3] >= 'a' && s[3] <= 'z' || s[3] >= 'A' && s[3] <= 'Z', false, "");
        return true;
    };

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

            memset(binaryCharSetMatrix + *v1, value, static_cast<uint64>(*v2) - *v1 + 1);
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

            memset(binaryCharSetMatrix + v1, value, static_cast<uint64>(v2) - v1 + 1);
        } break;
        }

        return true;
    };

    return true;
}

bool Instance::ProcessBinaryDataCharset(std::string_view include, std::string_view exclude)
{
    if (include == DEFAULT_BINARY_INCLUDE_CHARSET && exclude == DEFAULT_BINARY_EXCLUDE_CHARSET) {
        memset(context.binaryCharSetMatrix, true, BINARY_CHARSET_MATRIX_SIZE);
        return true;
    }

    memset(context.binaryCharSetMatrix, false, BINARY_CHARSET_MATRIX_SIZE);
    CHECK(FillCharSetMatrix(context.binaryCharSetMatrix, include, true), false, "");
    CHECK(FillCharSetMatrix(context.binaryCharSetMatrix, exclude, false), false, "");

    return true;
}

bool Instance::DropStrings(
      bool dropAscii,
      bool dropUnicode,
      const std::filesystem::path& logPath,
      bool simpleLogFormat,
      uint32 minimumSize,
      uint32 maximumSize,
      std::string_view charSet,
      bool identifyArtefacts)
{
    CHECK(context.initialized, false, "");
    CHECK(object.IsValid(), false, "");

    context.zones.Clear();
    context.findings.clear();
    context.occurences.clear();
    context.objectPaths.clear();

    CHECK(dropAscii || dropUnicode, false, "");

    auto dropper = static_cast<Text*>(context.textDropper.get());
    CHECK(dropper->SetAscii(dropAscii), false, "");
    CHECK(dropper->SetUnicode(dropUnicode), false, "");
    CHECK(dropper->SetMinLength(minimumSize), false, "");
    CHECK(dropper->SetMaxLength(maximumSize), false, "");

    memset(context.stringsCharSetMatrix, false, STRINGS_CHARSET_MATRIX_SIZE);
    CHECK(FillCharSetMatrix(context.stringsCharSetMatrix, charSet, true), false, "");
    dropper->SetMatrix(context.stringsCharSetMatrix);

    ArtefactIdentificationCallback cb = identifyArtefacts ? &IdentifyArtefact : nullptr;
    std::vector<PluginClassification> plugins{};
    if (identifyArtefacts) {
        const auto& subcategories = CATEGORY_TO_SUBCATEGORY_MAP.at(Category::SpecialStrings);
        for (const auto& v : subcategories) {
            plugins.emplace_back(PluginClassification{ Category::SpecialStrings, v });
        }
    }
    plugins.emplace_back(PluginClassification{ dropper->GetCategory(), dropper->GetSubcategory() });

    DataCache& cache = object->GetData();
    if (this->computeForFile) {
        CHECK(ProcessObjects(plugins, 1, cache.GetSize(), false, cb), false, "");
    } else {
        for (const auto& zone : selectedZones) {
            CHECK(ProcessObjects(plugins, zone.start, zone.end, false, cb), false, "");
        }
    }

    auto logFile = InitLogFile(logPath, areas, simpleLogFormat);
    CHECK(logFile.has_value(), false, "");

    struct Defer {
        std::ofstream& o;
        ~Defer()
        {
            o.close();
        }
    } _{ .o = *logFile };

    CHECK(logFile->good(), false, "");

    if (!simpleLogFormat) {
        WriteSummaryToLog(*logFile, context.occurences);
    }

    for (const auto& f : context.findings) {
        CHECK(WriteToLog(*logFile, f.start, f.end, f.result, context.textDropper, !simpleLogFormat, simpleLogFormat), false, "");
    }

    return true;
}
} // namespace GView::GenericPlugins::Droppper
