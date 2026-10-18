#include "Internal.hpp"
#include "DissasmAnalysisExport.hpp"

#include <fstream>
#include <optional>
#include <sstream>

using namespace GView::App;
using namespace GView::View;

namespace
{
// The window given to a type plugin by the headless analysis (GView analyze): nothing is shown, the settings of the disassembly viewer
// are kept, the other viewers and the panels are dropped (the process ends after the analysis)
class HeadlessWindow : public WindowInterface
{
    Reference<GView::Object> object;

  public:
    std::optional<DissasmViewer::Settings> dissasmSettings;

    explicit HeadlessWindow(Reference<GView::Object> object) : object(object)
    {
    }
    Reference<GView::Object> GetObject() override
    {
        return object;
    }
    bool AddPanel(Pointer<TabPage> /*page*/, bool /*vertical*/) override
    {
        return true;
    }
    bool CreateViewer(BufferViewer::Settings&) override
    {
        return true;
    }
    bool CreateViewer(ImageViewer::Settings&) override
    {
        return true;
    }
    bool CreateViewer(GridViewer::Settings&) override
    {
        return true;
    }
    bool CreateViewer(DissasmViewer::Settings& settings) override
    {
        // the data of the settings belongs to the viewer that receives them: here, to the analysis
        if (!dissasmSettings.has_value()) {
            dissasmSettings.emplace(settings);
            settings.data = nullptr;
        }
        return true;
    }
    bool CreateViewer(TextViewer::Settings&) override
    {
        return true;
    }
    bool CreateViewer(ContainerViewer::Settings&) override
    {
        return true;
    }
    bool CreateViewer(LexicalViewer::Settings&) override
    {
        return true;
    }
    Reference<ViewControl> GetCurrentView() override
    {
        return nullptr;
    }
    uint32 GetViewsCount() override
    {
        return 0;
    }
    Reference<ViewControl> GetViewByIndex(uint32) override
    {
        return nullptr;
    }
    bool SetViewByIndex(uint32) override
    {
        return false;
    }
    GView::CommonInterfaces::QueryInterface* GetQueryInterface() override
    {
        return nullptr;
    }
    Reference<GView::Utils::SelectionZoneInterface> GetSelectionZoneInterfaceFromViewerCreation(BufferViewer::Settings&) override
    {
        return nullptr;
    }
};

// a JSON file given on the command line (an annotations / signatures file); false (and the reason) when it can not be read or parsed
bool ReadJsonFile(const std::filesystem::path& path, std::string_view what, nlohmann::json& document, std::string& error)
{
    std::ifstream stream(path, std::ios::binary);
    std::stringstream text;
    if (!stream || !(text << stream.rdbuf())) {
        error = "Unable to read the " + std::string(what) + " file!";
        return false;
    }
    document = nlohmann::json::parse(text.str(), nullptr, false);
    if (document.is_discarded()) {
        error = "The " + std::string(what) + " file is not a valid JSON file!";
        return false;
    }
    return true;
}
} // namespace

bool Instance::AnalyzeFile(const std::filesystem::path& path, const AnalyzeOptions& options, std::string& json, std::string& error)
{
    // the files of the options are read first: a bad file stops before the (long) analysis
    nlohmann::json annotations, signatures, signaturesOutput;
    DissasmViewer::DissasmAnalysisOptions analysisOptions;
    if (!options.annotations.empty()) {
        if (!ReadJsonFile(options.annotations, "annotations", annotations, error))
            return false;
        analysisOptions.annotations = &annotations;
    }
    if (!options.signatures.empty()) {
        if (!ReadJsonFile(options.signatures, "signatures", signatures, error))
            return false;
        analysisOptions.signatures = &signatures;
    }
    if (!options.signaturesOutput.empty())
        analysisOptions.signaturesOutput = &signaturesOutput;
    const std::string_view typeName = options.typeName;
    auto file = std::make_unique<AppCUI::OS::File>();
    if (!file->OpenRead(path)) {
        error = "Unable to open the file!";
        return false;
    }
    GView::Utils::DataCache cache;
    if (!cache.Init(std::move(file), this->defaultCacheSize)) {
        error = "Unable to read the file!";
        return false;
    }
    // the same identification as a file that is opened (Add), without the dialogs: the first type that matches, or the given one
    const std::u16string fullPath = path.u16string();
    const std::u16string name     = path.filename().u16string();
    const auto dot                = fullPath.find_last_of(u'.');
    const auto extensionHash      = GView::Type::Plugin::ExtensionToHash(dot != std::u16string::npos ? std::u16string_view(fullPath).substr(dot) : std::u16string_view());
    std::u16string newName        = name;
    const auto method             = typeName.empty() ? OpenMethod::FirstMatch : OpenMethod::ForceType;
    auto plugin                   = IdentifyTypePlugin(name, fullPath, cache, extensionHash, method, typeName, newName);
    if (!plugin.IsValid() || plugin == static_cast<const void*>(&this->defaultPlugin)) {
        error = "The type of the file is not known (use --type:<type>)!";
        return false;
    }
    if (!Security::RestrictedMode::Internal::IsPluginAllowed(plugin->GetName())) {
        error = "The type of the file is not allowed by the policy!";
        return false;
    }
    auto contentType = plugin->CreateInstance();
    if (!contentType) {
        error = "The type plugin could not read the file!";
        return false;
    }
    auto object = std::make_unique<GView::Object>(GView::Object::Type::File, std::move(cache), contentType, newName, fullPath, 0);
    HeadlessWindow window(object.get());
    if (!plugin->PopulateWindow(&window)) {
        error = "The type plugin could not read the file!";
        return false;
    }
    if (!window.dissasmSettings.has_value()) {
        error = "The type of the file has no disassembly view!";
        return false;
    }
    if (!DissasmViewer::BuildAnalysisJson(object.get(), window.dissasmSettings.value(), json, error, analysisOptions))
        return false;
    if (!options.signaturesOutput.empty()) {
        std::ofstream stream(options.signaturesOutput, std::ios::binary);
        if (!stream || !(stream << signaturesOutput.dump(2) << "\n")) {
            error = "Unable to write the signatures file!";
            return false;
        }
    }
    return true;
}
