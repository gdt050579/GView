#pragma once

#include "GView.hpp"
#include "ServiceInterface.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{
using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;

/**
 * Dialog for displaying analysis results from a service (e.g., VirusTotal)
 * Note: Detailed results display will be implemented in a future task
 */
class AnalysisResultsDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    AnalysisResult storedResult;  // Store result for future detailed display
    Reference<Label> statusLabel;
    Reference<ListView> resultsList;  // Placeholder for future detailed results
    Reference<Button> closeBtn;

  public:
    AnalysisResultsDialog(const AnalysisResult& result);
    void OnButtonPressed(Reference<Button> b) override;
};

/**
 * Main dialog for computing hashes and initiating analysis
 */
class HashAnalyzerDialog : public Window, public Handlers::OnButtonPressedInterface
{
  private:
    Reference<GView::Object> object;
    
    // UI components
    Reference<RadioBox> computeForFile;
    Reference<RadioBox> computeForSelection;
    Reference<ListView> hashesList;
    Reference<Button> computeBtn;
    
    // Service selection components
    Reference<Label> serviceLabel;
    Reference<ComboBox> serviceSelector;
    Reference<Button> analyzeBtn;
    
    Reference<Button> closeBtn;
    
    std::vector<TypeInterface::SelectionZone> selectedZones;
    
    // Stored hash values after computation
    std::string md5Hash;
    std::string sha1Hash;
    std::string sha256Hash;
    bool hashesComputed;

    void ComputeHash();
    void OnAnalyze();
    void PopulateServiceSelector();

  public:
    HashAnalyzerDialog(Reference<GView::Object> object);
    void OnButtonPressed(Reference<Button> b) override;
    bool OnEvent(Reference<Control> c, Event eventType, int id) override;
};

} // namespace GView::GenericPlugins::HashAnalyzer


