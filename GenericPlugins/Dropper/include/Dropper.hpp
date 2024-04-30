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
constexpr std::string_view DEFAULT_INCLUDE_CHARSET{ "\\x00-\\xff" };
constexpr std::string_view DEFAULT_EXCLUDE_CHARSET{ "" };
constexpr int32 CHARSET_MATRIX_SIZE{ 256 };
constexpr int8 HEX_NUMBER_SIZE{ 4 };

class Instance
{
  private:
    Reference<GView::Object> object;

    inline static struct Context {
        std::vector<std::unique_ptr<IDrop>> objectDroppers;
        std::unique_ptr<IDrop> textDropper{ nullptr };
        bool initialized{ false };

        bool textMatrix[CHARSET_MATRIX_SIZE]{ true };
    } context;

    std::ofstream logFile;
    uint64 objectId{ 0 };

    std::map<std::string_view, std::unique_ptr<std::ofstream>> singleFiles;

    std::vector<std::pair<uint64, uint64>> areas;
    std::vector<GView::TypeInterface::SelectionZone> selectedZones;
    bool computeForFile{ true };

    inline static constexpr uint32 SEPARATOR_LENGTH = 80;

  private:
    bool ProcessBinaryDataCharset(std::string_view include, std::string_view exclude);

  public:
    Instance() = default;
    ~Instance();

    bool Init(Reference<GView::Object> object);
    void UnInitLogs();

    BufferView GetPrecachedBuffer(uint64 offset, DataCache& cache);
    bool InitLogFile(const std::vector<std::pair<uint64, uint64>>& areas);
    bool WriteSummaryToLog(std::map<std::string_view, uint32>& occurences);
    bool WriteToLog(uint64 start, uint64 end, Result result, std::unique_ptr<IDrop>& dropper);
    bool WriteToFile(uint64 start, uint64 end, std::unique_ptr<IDrop>& dropper, Result result);
    bool Process();
    bool ProcessObjects(uint64 offset, uint64 size);
    bool ToggleHighlighting(bool value, GView::Utils::ZonesList& zones);

    bool HandleComputationAreas();
    bool IsComputingFile() const;
    bool SetComputingFile(bool value);

    bool DropBinaryData(
          std::string_view filename,
          bool overwriteFile,
          bool openFile,
          std::string_view includedCharSet,
          std::string_view excludedCharSet,
          Reference<Window> parentWindow);
};
} // namespace GView::GenericPlugins::Droppper
