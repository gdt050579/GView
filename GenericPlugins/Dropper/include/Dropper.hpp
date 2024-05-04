#pragma once

#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <set>

#include "SpecialStrings.hpp"
#include "Executables.hpp"
#include "Multimedia.hpp"
#include "HtmlObjects.hpp"
#include "Images.hpp"
#include "Archives.hpp"
#include "Cryptographic.hpp"

using namespace GView::Utils;
using namespace GView::GenericPlugins::Droppper::SpecialStrings;
using namespace GView::GenericPlugins::Droppper::Executables;
using namespace GView::GenericPlugins::Droppper::Multimedia;
using namespace GView::GenericPlugins::Droppper::HtmlObjects;
using namespace GView::GenericPlugins::Droppper::Images;
using namespace GView::GenericPlugins::Droppper::Archives;
using namespace GView::GenericPlugins::Droppper::Cryptographic;

namespace GView::GenericPlugins::Droppper
{
constexpr std::string_view DEFAULT_BINARY_INCLUDE_CHARSET{ "\\x00-\\xff" };
constexpr std::string_view DEFAULT_BINARY_EXCLUDE_CHARSET{ "" };
constexpr int32 BINARY_CHARSET_MATRIX_SIZE{ 256 };
constexpr int8 HEX_NUMBER_SIZE{ 4 };

struct PluginClassification {
    Category category{};
    Subcategory subcategory{};
};

class Instance
{
  private:
    Reference<GView::Object> object;

    inline static struct Context {
        std::vector<std::unique_ptr<IDrop>> objectDroppers;
        std::unique_ptr<IDrop> textDropper{ nullptr };
        bool initialized{ false };

        bool binaryCharSetMatrix[BINARY_CHARSET_MATRIX_SIZE]{};

        GView::Utils::ZonesList zones;
        std::vector<Finding> findings;
        std::map<std::string_view, uint32> occurences;

        std::set<std::filesystem::path> objectPaths;

        bool stringsCharSetMatrix[STRINGS_CHARSET_MATRIX_SIZE]{};
    } context;

    uint64 objectId{ 0 };

    std::vector<std::pair<uint64, uint64>> areas;
    std::vector<GView::TypeInterface::SelectionZone> selectedZones;
    bool computeForFile{ true };

    inline static constexpr uint32 SEPARATOR_LENGTH = 80;

  private:
    bool ProcessBinaryDataCharset(std::string_view include, std::string_view exclude);
    bool FillCharSetMatrix(bool binaryCharSetMatrix[BINARY_CHARSET_MATRIX_SIZE], std::string_view s, bool value);

  public:
    Instance() = default;

    bool Init(Reference<GView::Object> object);

    BufferView GetPrecachedBuffer(uint64 offset, DataCache& cache);
    std::optional<std::ofstream> InitLogFile(const std::filesystem::path& p, const std::vector<std::pair<uint64, uint64>>& areas, bool noHeader = false);
    bool WriteSummaryToLog(std::ofstream& f, std::map<std::string_view, uint32>& occurences);
    bool WriteToLog(std::ofstream& f, uint64 start, uint64 end, Result result, std::unique_ptr<IDrop>& dropper, bool addValue = false, bool writeValueOnly = false);
    bool WriteToFile(std::filesystem::path path, uint64 start, uint64 end, std::unique_ptr<IDrop>& dropper, Result result);
    bool DropObjects(
          const std::vector<PluginClassification>& plugins,
          const std::filesystem::path& path,
          const std::filesystem::path& logPath,
          bool recursive,
          bool writeLog,
          bool highlightObjects);
    bool ProcessObjects(const std::vector<PluginClassification>& plugins, uint64 offset, uint64 size, bool recursive, ArtefactIdentificationCallback identify = nullptr);
    bool SetHighlighting(bool value, bool warn = false);

    bool HandleComputationAreas();
    bool IsComputingFile() const;
    bool SetComputingFile(bool value);
    const std::set<std::filesystem::path>& GetObjectsPaths() const;
    const std::vector<Finding>& GetFindings() const;

    bool DropBinaryData(
          std::string_view filename,
          bool overwriteFile,
          bool openFile,
          std::string_view includedCharSet,
          std::string_view excludedCharSet,
          Reference<Window> parentWindow);

    bool DropStrings(
          bool dropAscii,
          bool dropUnicode,
          const std::filesystem::path& path,
          bool simpleLogFormat,
          uint32 minimumSize,
          uint32 maximumSize,
          std::string_view charSet,
          bool identifyArtefacts);
};
} // namespace GView::GenericPlugins::Droppper
