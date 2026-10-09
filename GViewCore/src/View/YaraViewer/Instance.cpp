#include "YaraViewer.hpp"
#include <algorithm>
#include <cstdlib> 
#include <iostream>
#include <fstream>   
#include <string>    
#include <codecvt>
#include <locale>

#include <windows.h>
#include <shellapi.h>
#include "capstone/capstone.h"

#undef MessageBox

using namespace GView::View::YaraViewer;
using namespace AppCUI::Input;
namespace fs = std::filesystem;

Config Instance::config;

constexpr int startingX = 5;


// Constructor
Instance::Instance(Reference<GView::Object> _obj, Settings* _settings)
    : ViewControl("Yara View", UserControlFlags::ShowVerticalScrollBar | UserControlFlags::ScrollBarOutsideControl), settings(nullptr)
{
    this->obj = _obj;

    this->cursorRow     = 0;
    this->cursorCol     = 0;
    this->startViewLine = 0;
    this->leftViewCol   = 0;

    this->selectionActive    = false;
    this->selectionAnchorRow = 0;
    this->selectionAnchorCol = 0;

    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }
    else
    {
        // default setup
        this->settings.reset(new SettingsData());
    }

    if (config.Loaded == false)
        config.Initialize();

    layout.visibleLines = 1;
    layout.maxCharactersPerLine = 10;
}


// --- Metode ViewControl (Interfața Standard) ---
bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value){ NOT_IMPLEMENTED(false) }
bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error){ NOT_IMPLEMENTED(false) }
void Instance::SetCustomPropertyValue(uint32 propertyID){} //NOT IMPLEMENTED
bool Instance::IsPropertyValueReadOnly(uint32 propertyID){ NOT_IMPLEMENTED(false) }
const vector<Property> Instance::GetPropertiesList(){ return {}; }

bool Instance::GoTo(uint64 offset){ NOT_IMPLEMENTED(false) }
bool Instance::Select(uint64 offset, uint64 size) { NOT_IMPLEMENTED(false) }


// --- Dialoguri ---
bool Instance::ShowGoToDialog(){ NOT_IMPLEMENTED(false) }
bool Instance::ShowCopyDialog(){ NOT_IMPLEMENTED(false) }
bool Instance::ShowFindDialog()
{
    // 1. Inițializare dialog și preluare input utilizator
    FindDialog dlg;
    if (dlg.Show() != Dialogs::Result::Ok)
        return true;

    std::string text = dlg.resultText;
    if (text.empty())
        return true;

    // 2. Salvare stare și refresh UI (activează butonul 'Find Next' și forțează focus)
    this->lastSearchText = text;
    this->isButtonFindPressed = true;
    this->SetFocus();

    // 3. Pregătire căutare Case-Insensitive (convertim inputul la lowercase)
    std::string textToFindLower = text;
    std::transform(textToFindLower.begin(), textToFindLower.end(), textToFindLower.begin(), ::tolower);

    uint32 totalLines = (uint32) yaraLines.size();
    if (totalLines == 0)
        return true;

    // 4. Începem căutarea de la începutul fișierului
    uint32 startIdx = 0;

    for (uint32 i = 0; i < totalLines; i++) {
        // Implementare wrap-around (când ajunge la final, o ia de la capăt)
        uint32 currentIdx = (startIdx + i) % totalLines;

        const auto& line = yaraLines[currentIdx];

        // 5. Verificare potrivire pe linia curentă (tot lowercase)
        std::string lineLower = line.text;
        std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(), ::tolower);

        size_t foundPos = lineLower.find(textToFindLower);

        if (foundPos != std::string::npos) {

            // A. Dacă linia găsită este ascunsă (pliată), căutăm header-ul părinte și îl expandăm
            if (!line.isVisible) {
                for (int k = (int) currentIdx - 1; k >= 0; k--) {
                    if (yaraLines[k].type == LineType::FileHeader) {
                        if (!yaraLines[k].isExpanded) {
                            ToggleFold(k);
                        }
                        break;// Am găsit header-ul, ne oprim
                    }
                }
            }

            // B. Mapăm indexul real la cel vizual și evidențiem rezultatul (Highlight Galben)
            for (size_t v = 0; v < visibleIndices.size(); v++) {
                if (visibleIndices[v] == currentIdx) {
                    SelectMatch((uint32) v, foundPos, (uint32) textToFindLower.length());
                    return true;
                }
            }
        }
    }

    // 6. Nicio potrivire găsită după scanarea completă
    AppCUI::Dialogs::MessageBox::ShowError("Not Found", "Text '" + text + "' not found!");
    return true;
}


// --- Desenare & UI ---
void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
    // 1. Validare spațiu (nu desenăm dacă zona este invizibilă)
    if (height == 0)
        return;

    ColorPair cfgColor = { Color::White, Color::Transparent };

    // 2. Pregătire text informativ
    LocalString<128> info;
    info.Format("Ln: %u | Col: %u", this->cursorRow + 1, this->cursorCol + 1);

    // 3. Randare efectivă
    renderer.Clear(' ', cfgColor);
    renderer.WriteSingleLineText(1, 0, info.GetText(), cfgColor);
} 
void Instance::Paint(Graphics::Renderer& renderer)
{
    // 1. Definiții Paletă de Culori
    ColorPair textNormal    = ColorPair{ Color::White, Color::Transparent };
    ColorPair textCursor    = ColorPair{ Color::Black, Color::White };
    ColorPair arrowColor    = ColorPair{ Color::Gray, Color::Transparent };
    ColorPair marginColor   = ColorPair{ Color::Gray, Color::Transparent };
    ColorPair textSelection = ColorPair{ Color::Black, Color::Silver };
    ColorPair warningColor  = ColorPair{ Color::Olive, Color::Transparent };

    ColorPair ruleBlockColor = ColorPair{ Color::Green, Color::Transparent };
    ColorPair checkboxColor  = ColorPair{ Color::Red, Color::Transparent };    // pt [x]
    ColorPair headerColor    = ColorPair{ Color::Yellow, Color::Transparent }; // pt nume fisier
    ColorPair infoColor      = ColorPair{ Color::Red, Color::Transparent };
    ColorPair matchColor     = ColorPair{ Color::Teal, Color::Transparent };
    ColorPair foldColor = ColorPair{ Color::Aqua, Color::Transparent };

    // 2. Dimensiuni Viewport & Layout
    uint32 rows           = this->GetHeight();
    uint32 width          = this->GetWidth();
    const int LEFT_MARGIN = 4;

    // 3. Coordonate Selecție
    uint32 selStartRow = this->cursorRow;
    uint32 selStartCol = this->cursorCol;
    uint32 selEndRow   = this->selectionAnchorRow;
    uint32 selEndCol   = this->selectionAnchorCol;

    GetRulesFiles();  // Lazy loading date

    // Asigurăm popularea cache-ului de linii vizibile
    if (visibleIndices.empty() && !yaraLines.empty())
        UpdateVisibleIndices();

    if (this->selectionActive) {
        // Swap dacă selecția a fost făcută de jos în sus sau dreapta->stânga
        if (selStartRow > selEndRow || (selStartRow == selEndRow && selStartCol > selEndCol)) {
            std::swap(selStartRow, selEndRow);
            std::swap(selStartCol, selEndCol);
        }
    }

    // ========================================================================
    // MAIN RENDER LOOP (Iterăm prin rândurile vizibile pe ecran)
    // ========================================================================

    for (uint32 tr = 0; tr < rows; tr++) {

        // A. Mapare: Index Ecran (tr) -> Index Date
        uint32 visualIndex = this->startViewLine + tr;
        if (visualIndex >= visibleIndices.size())
            break;   // Am terminat de desenat liniile disponibile

        size_t realIndex     = visibleIndices[visualIndex];
        const LineInfo& info = yaraLines[realIndex];
        std::string displayText = info.text;

        // B. Decoratori Text (Prefixe/Sufixe vizuale)
        int checkboxStart = -1;
        int checkboxEnd   = -1;
        int arrowStart    = -1;

        // --- ADAUGĂM VIZUAL SĂGEATA DE EXPANDARE ---
        if (info.type == LineType::FileHeader) {
            // Prefix: Checkbox [ ]
            std::string prefix = info.isChecked ? "[x] " : "[ ] ";
            displayText        = prefix + displayText;

            checkboxStart = 0;
            checkboxEnd   = 4; 

            // Suffix: Săgeata de Fold > sau v
            std::string arrow = info.isExpanded ? " v" : " >";
            arrowStart        = (int) displayText.length();
            displayText += arrow;
        } else if (info.indentLevel > 0) {
            displayText.insert(0, "    ");
        }

        // C. Logică Dual-Color pentru OffsetHeader ("File offset: 0x...")
        int splitColorIndex = -1; 
        if (info.type == LineType::OffsetHeader) {
            size_t pos = displayText.find("0x");
            if (pos != std::string::npos) {
                splitColorIndex = (int) pos;
            }
        }

        // D. Desenare Elemente Margine (Gutter)
        renderer.WriteSpecialCharacter(LEFT_MARGIN - 1, tr, SpecialChars::BoxVerticalSingleLine, marginColor);
        
        // Indicator linia curentă "->"
        if (visualIndex == this->cursorRow) {
            renderer.WriteSingleLineText(1, tr, "->", arrowColor);
        }

        // ====================================================================
        // CHARACTER RENDER LOOP (Desenare conținut text caracter cu caracter)
        // ====================================================================

        if (displayText.length() > this->leftViewCol) {
            // Tăiem partea din stânga dacă avem scroll orizontal
            std::string_view view = displayText;
            view                  = view.substr(this->leftViewCol);

            for (uint32 i = 0; i < view.length(); i++) {
                // Nu desenăm în afara ferestrei
                if (LEFT_MARGIN + i >= width)
                    break;

                uint32 absCol          = this->leftViewCol + i;
                ColorPair currentColor = textNormal; // Default

                // ------------------------------------------------------------
                // LAYER 1: Culoarea de bază (Syntax Highlighting)
                // ------------------------------------------------------------
                if (info.type == LineType::OffsetHeader) {
                    // Split: Alb până la "0x", Verde după
                    if (splitColorIndex != -1 && absCol >= splitColorIndex) {
                        currentColor = ruleBlockColor; 
                    } else {
                        currentColor = textNormal;
                    }
                } else if (info.type == LineType::Warning) { 
                    currentColor = warningColor;
                } else if (info.type == LineType::RuleContent)
                    currentColor = ruleBlockColor;
                else if (info.type == LineType::Info)
                    currentColor = infoColor;
                else if (info.type == LineType::Match)
                    currentColor = matchColor;
                else if (info.type == LineType::FileHeader) {
                    // Culori specifice Header (Checkbox vs Text vs Arrow)
                    if (absCol >= checkboxStart && absCol < checkboxEnd)
                        currentColor = checkboxColor;
                    else if (arrowStart != -1 && absCol >= arrowStart)
                        currentColor = foldColor;
                    else
                        currentColor = headerColor;
                }

                // ------------------------------------------------------------
                // LAYER 2: Highlight Căutare (Override peste bază)
                // ------------------------------------------------------------
                if (this->searchActive && realIndex == this->searchResultRealIndex) {
                    if (absCol >= this->searchResultStartCol && absCol < (this->searchResultStartCol + this->searchResultLen)) {
                        currentColor = ColorPair{ Color::Black, Color::Yellow };
                    }
                }

                // ------------------------------------------------------------
                // LAYER 3: Selecție Utilizator (Override peste Search)
                // ------------------------------------------------------------
                if (this->selectionActive) {
                    bool isSelected = false;
                    // Logica de selecție multi-line
                    if (visualIndex > selStartRow && visualIndex < selEndRow) {
                        isSelected = true; // Linie complet interioară
                    } else if (visualIndex == selStartRow && visualIndex == selEndRow) {
                        // Selecție pe o singură linie
                        if (absCol >= selStartCol && absCol < selEndCol)
                            isSelected = true;
                    } else if (visualIndex == selStartRow) {
                        // Prima linie a selecției
                        if (absCol >= selStartCol)
                            isSelected = true;
                    } else if (visualIndex == selEndRow) {
                        // Ultima linie a selecției
                        if (absCol < selEndCol)
                            isSelected = true;
                    }

                    if (isSelected) {
                        currentColor = textSelection;
                    }
                }

                // ------------------------------------------------------------
                // LAYER 4: Cursor 
                // ------------------------------------------------------------
                if (visualIndex == this->cursorRow && absCol == this->cursorCol) {
                    currentColor = textCursor;
                }
                // Desenare efectivă caracter
                renderer.WriteCharacter(LEFT_MARGIN + i, tr, view[i], currentColor);
            }

            // E. Fill Background (pentru linii colorate complet, ex: RuleContent)
            if (info.type == LineType::RuleContent) {
                int startFill = LEFT_MARGIN + (int) view.length();
                for (int k = startFill; k < (int) width; k++) {
                    bool isCursorHere = (visualIndex == this->cursorRow && (this->leftViewCol + (k - LEFT_MARGIN)) == this->cursorCol);
                    renderer.WriteCharacter(k, tr, ' ', isCursorHere ? textCursor : ruleBlockColor);
                }
            }
        }

        // F. Desenare Cursor dacă este la finalul liniei (după text)
        if (visualIndex == this->cursorRow && this->cursorCol == displayText.length()) {
            if (this->cursorCol >= this->leftViewCol) {
                int screenX = (int) (this->cursorCol - this->leftViewCol) + LEFT_MARGIN;
                if (screenX < (int) width) {
                    renderer.WriteCharacter(screenX, tr, ' ', textCursor);
                }
            }
        }
    }
}
void Instance::OnAfterResize(int newWidth, int newHeight)
{
    layout.visibleLines = GetHeight();
    if (layout.visibleLines > 0)
        layout.visibleLines--;
    layout.maxCharactersPerLine = GetWidth() - startingX /*left*/ - startingX /*right*/;
}
void Instance::AddMatchToUI(const std::string& ruleName, const std::string& tags, const std::string& author, const std::string& severity, const std::vector<std::string>& strings, const std::string& filePath)
{
    yaraLines.push_back({ "    [MATCH] Rule: " + ruleName, LineType::Match });
    if (!tags.empty())
        yaraLines.push_back({ "    Tags: " + tags, LineType::Normal });
    if (!author.empty())
        yaraLines.push_back({ "    Author: " + author, LineType::Normal });
    if (!severity.empty())
        yaraLines.push_back({ "    Severity: " + severity, LineType::Normal });

    for (const auto& s : strings) {
        yaraLines.push_back({ "        " + s, LineType::RuleContent });
        yaraLines.push_back({ "        At:", LineType::Normal });

        // Hex Context
        auto ctx = ExtractHexContextFromYaraMatch(s, filePath);
        for (auto& ctxPair : ctx) {
            LineInfo infoLine;

            std::string prefix = "           ";

            if (ctxPair.first.find("0x") == 0) {
                prefix += "    ";
            }
            infoLine.text = prefix + ctxPair.first;
            infoLine.type = ctxPair.second;
            yaraLines.push_back(infoLine);
        }

        // Disassembly
        auto disasmLines = ExtractDisassemblyFromYaraMatch(s, filePath);
        for (auto& disPair : disasmLines) {
            LineInfo infoLine;
            if (disPair.first.find("Disassembly:") != std::string::npos) {
                infoLine.text = "           " + disPair.first;
            } else {
                infoLine.text = "               " + disPair.first;
            }

            infoLine.type = disPair.second;
            yaraLines.push_back(infoLine);
        }
    }
    yaraLines.push_back({ "", LineType::Normal });
}


// --- Serializare Setări ---
std::string_view Instance::GetCategoryNameForSerialization() const { return "YaraViewer"; }
bool Instance::AddCategoryBeforePropertyNameWhenSerializing() const { return true; }


// --- Input Handling ---
bool Instance::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    if (!yaraExecuted) {
        commandBar.SetCommand(Commands::YaraRunCommand.Key, Commands::YaraRunCommand.Caption, Commands::YaraRunCommand.CommandId);
    }
    commandBar.SetCommand(Commands::ViewRulesCommand.Key, Commands::ViewRulesCommand.Caption, Commands::ViewRulesCommand.CommandId);
    commandBar.SetCommand(Commands::EditRulesCommand.Key, Commands::EditRulesCommand.Caption, Commands::EditRulesCommand.CommandId);
    if (!yaraExecuted) {
        commandBar.SetCommand(Commands::SelectAllCommand.Key, "Select All", Commands::SelectAllCommand.CommandId);
        commandBar.SetCommand(Commands::DeselectAllCommand.Key, "Deselect All", Commands::DeselectAllCommand.CommandId);
    }
    commandBar.SetCommand(Commands::FindTextCommand.Key, "Find Text", Commands::FindTextCommand.CommandId);

    if (isButtonFindPressed) {
        commandBar.SetCommand(Commands::FindNextCommand.Key, "Find Next", Commands::FindNextCommand.CommandId);
    }
    if (yaraExecuted) {
        commandBar.SetCommand(Commands::SaveReportCommand.Key, "Save Report", Commands::SaveReportCommand.CommandId);
    }
    return false;
}
bool Instance::UpdateKeys(KeyboardControlsInterface* interfaceParam)
{
    interfaceParam->RegisterKey(&Commands::YaraRunCommand);
    interfaceParam->RegisterKey(&Commands::ViewRulesCommand);
    interfaceParam->RegisterKey(&Commands::EditRulesCommand);
    interfaceParam->RegisterKey(&Commands::SelectAllCommand);
    interfaceParam->RegisterKey(&Commands::DeselectAllCommand);
    interfaceParam->RegisterKey(&Commands::FindTextCommand);
    interfaceParam->RegisterKey(&Commands::FindNextCommand);
    interfaceParam->RegisterKey(&Commands::SaveReportCommand);

    return true;
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    // Procesăm doar evenimentele de tip Comandă (Butoane, Taste, Meniu)
    if (eventType != Event::Command)
        return false;

    // --- COMMAND DISPATCHER ---

    if (ID == Commands::YaraRunCommand.CommandId) { // Run Yara
        auto result = AppCUI::Dialogs::MessageBox::ShowOkCancel("Run Yara", "Are you sure?");

        if (result == Dialogs::Result::Ok) {
            yaraExecuted = false;
            RunYara();
        }

    } else if (ID == Commands::ViewRulesCommand.CommandId) { //View Rules
        yaraGetRulesFiles = false;
        yaraExecuted      = false;
        GetRulesFiles();

    } else if (ID == Commands::EditRulesCommand.CommandId) { // Edit Rules
        yaraGetRulesFiles = false;
        GetRulesFiles();

        fs::path currentPath = fs::current_path();
        fs::path rootPath    = currentPath.parent_path().parent_path();
        fs::path yaraRules   = rootPath / "3rdPartyLibs" / "rules";

        if (!fs::exists(yaraRules)) {
            fs::create_directories(yaraRules);
        }

        // Deschidem folderul
        ShellExecuteA(NULL, "explore", yaraRules.string().c_str(), NULL, NULL, SW_SHOWNORMAL);

        auto result = AppCUI::Dialogs::MessageBox::ShowOkCancel(
              "Edit Rules", "Rules folder opened.\n\nYou can Add, Edit or Delete .yara files now.\n\nClick [OK] when you are done to refresh the list.");

        // Refresh automat la OK
        if (result == Dialogs::Result::Ok) {
            yaraGetRulesFiles = false;
            GetRulesFiles();
        }
    } else if (ID == Commands::SelectAllCommand.CommandId) { // Select All
        SelectAllRules();
        return true;
    } else if (ID == Commands::DeselectAllCommand.CommandId) { // Deselect All  
        DeselectAllRules();
        return true;
    } else if (ID == Commands::FindNextCommand.CommandId) { // Find Next
        FindNext();
        return true;
    } else if (ID == Commands::SaveReportCommand.CommandId) { // Save Report
        ExportResults();
        return true;
    } else if (ID == Commands::FindTextCommand.CommandId) { // Find Text
        ShowFindDialog();
        return true;
    }

    return false;
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode)
{
    if (keyCode == (Key::Ctrl | Key::C)) {
        CopySelectionToClipboard();
        return true;
    }

    if (visibleIndices.empty())
        return false;

    auto GetCurrentLine = [&]() -> LineInfo& {
        size_t realIdx = visibleIndices[cursorRow];
        return yaraLines[realIdx];
    };

    if (keyCode == Key::Space) {
        if (cursorRow < visibleIndices.size()) {
            auto& line = GetCurrentLine();
            if (line.type == LineType::FileHeader) {
                line.isChecked = !line.isChecked;
            }
        }
        return true;
    }

    if (keyCode == Key::Enter) {
        if (cursorRow < visibleIndices.size()) {
            size_t realIdx = visibleIndices[cursorRow];
            if (yaraLines[realIdx].type == LineType::FileHeader) {
                ToggleFold(realIdx);
            }
        }
        return true;
    }

    if (keyCode == Key::Escape) {
        this->selectionActive     = false;
        this->searchActive        = false;
        this->isButtonFindPressed = false;
        this->SetFocus();
        this->lastSearchText.clear();
        return true;
    }

    // Navigare și Scroll
    uint32 pageHeight = this->GetHeight(); // Câte linii încap pe ecran

    switch (keyCode) {
    case Key::Right: {
        auto& line = GetCurrentLine(); 
        if (cursorCol < line.text.length()) {
            cursorCol++;
        }
        // Trecem la linia următoare doar dacă există în lista VIZIBILĂ
        else if (cursorRow + 1 < visibleIndices.size()) {
            cursorRow++;
            cursorCol = 0;

            // Check Scroll Jos la wrap-around
            if (cursorRow >= startViewLine + pageHeight)
                startViewLine++;
        }
    }
        MoveTo();
        return true;

    case Key::Left:
        if (cursorCol > 0)
            cursorCol--;
        else if (cursorRow > 0) {
            cursorRow--;
            // Luăm lungimea liniei ANTERIOARE vizibile
            size_t prevRealIdx = visibleIndices[cursorRow];
            cursorCol          = (uint32) yaraLines[prevRealIdx].text.length();

            // Check Scroll Sus la wrap-around
            if (cursorRow < startViewLine)
                startViewLine = cursorRow;
        }
        MoveTo();
        return true;

    case Key::Down:
        if (cursorRow + 1 < visibleIndices.size()) {
            cursorRow++;

            // Ajustare coloană (să nu fim în afara textului noii linii)
            auto& line = GetCurrentLine();
            if (cursorCol > line.text.length())
                cursorCol = (uint32) line.text.length();

            // Dacă cursorul coboară sub partea de jos a ecranului, tragem imaginea în jos
            if (cursorRow >= startViewLine + pageHeight) {
                startViewLine++;
            }
        }
        MoveTo(); // Actualizează poziția cursorului 
        return true;

    case Key::Up:
        if (cursorRow > 0) {
            cursorRow--;

            // Ajustare coloană
            auto& line = GetCurrentLine();
            if (cursorCol > line.text.length())
                cursorCol = (uint32) line.text.length();

            // Dacă cursorul urcă deasupra primei linii vizibile, tragem imaginea în sus
            if (cursorRow < startViewLine) {
                startViewLine = cursorRow;
            }
        }
        MoveTo();
        return true;

    //  Page Up / Page Down pentru navigare rapidă
    case Key::PageDown:
        if (cursorRow + pageHeight < visibleIndices.size()) {
            cursorRow += pageHeight;
            startViewLine += pageHeight; // Scroll pagină întreagă
        } else {
            cursorRow = (uint32) visibleIndices.size() - 1;
            if (visibleIndices.size() > pageHeight)
                startViewLine = (uint32) visibleIndices.size() - pageHeight;
        }
        MoveTo();
        return true;

    case Key::PageUp:
        if (cursorRow > pageHeight) {
            cursorRow -= pageHeight;
            if (startViewLine > pageHeight)
                startViewLine -= pageHeight;
            else
                startViewLine = 0;
        } else {
            cursorRow     = 0;
            startViewLine = 0;
        }
        MoveTo();
        return true;
    }

    return false;
}


// --- Mouse Handling ---
bool Instance::OnMouseWheel(int x, int y, AppCUI::Input::MouseWheel direction, AppCUI::Input::Key key)
{
    //Tratam evenimentul de scroll ca și o apăsare de tastă
    switch (direction) {
    case MouseWheel::Up:
        return OnKeyEvent(Key::Up, false);

    case MouseWheel::Down:
        return OnKeyEvent(Key::Down, false);

    case MouseWheel::Left:
        return OnKeyEvent(Key::Left, false);

    case MouseWheel::Right:
        return OnKeyEvent(Key::Right, false);
    }

    return false;
}
bool Instance::OnMouseDrag(int x, int y, AppCUI::Input::MouseButton button, AppCUI::Input::Key keyCode)
{
    if ((button & MouseButton::Left) == MouseButton::None)
        return false;
    if (yaraLines.empty())
        return false;

    // Actualizăm poziția cursorului în timp ce tragem
    ComputeMouseCoords(x, y, this->startViewLine, this->leftViewCol, this->yaraLines, this->cursorRow, this->cursorCol);

    // Activăm selecția dacă poziția s-a schimbat
    if (this->cursorRow != this->selectionAnchorRow || this->cursorCol != this->selectionAnchorCol) {
        this->selectionActive = true;
    }
    MoveTo(); // Auto-scroll dacă tragem mouse-ul în afara zonei vizibile
    return true;
}
void Instance::OnMousePressed(int x, int y, AppCUI::Input::MouseButton button, AppCUI::Input::Key keyCode)
{
    if ((button & MouseButton::Left) == MouseButton::None)
        return;
    if (visibleIndices.empty() || yaraLines.empty())
        return;

    // 1. Calculăm rândul vizual
    uint32 clickVisualRow = this->startViewLine + y;
    if (clickVisualRow >= visibleIndices.size())
        return;

    // 2. Calculăm coordonatele exacte (Rând și Coloană)
    ComputeMouseCoords(x, y, this->startViewLine, this->leftViewCol, this->yaraLines, this->cursorRow, this->cursorCol);

    // 3. Resetăm ancora selecției (Începem o nouă selecție)
    this->selectionAnchorRow = this->cursorRow;
    this->selectionAnchorCol = this->cursorCol;
    this->selectionActive    = false;

    // 4. Logica pentru Header (Checkbox / Fold)
    size_t realIndex = visibleIndices[clickVisualRow];
    LineInfo& line   = yaraLines[realIndex];

    int relX = (x - 4) + this->leftViewCol; // Ajustare pentru margine

    if (line.type == LineType::FileHeader) {
        // Verificăm click pe zona Checkbox "[ ]" 
        if (relX >= 0 && relX <= 2) {
            line.isChecked = !line.isChecked;
            return;
        }

        // Verificăm click pe zona Săgeată ">"
        int arrowStart = 4 + (int) line.text.length(); 
        if (relX >= arrowStart && relX <= arrowStart + 1) {
            ToggleFold(realIndex);
            return;
        }
    }

    MoveTo();
}
void Instance::ComputeMouseCoords(int x, int y, uint32 startViewLine, uint32 leftViewCol, const std::vector<LineInfo>& lines, uint32& outRow, uint32& outCol)
{
    const int LEFT_MARGIN = 4;

    // 1. Calculăm Rândul Vizual
    uint32 r = startViewLine + y;

    // Validăm limitele vizuale
    if (visibleIndices.empty()) {
        r = 0;
    } else if (r >= visibleIndices.size()) {
        r = (uint32) visibleIndices.size() - 1;
    }
    outRow = r;

    // 2. Calculăm Coloana Vizuală
    int val = (int) leftViewCol + (x - LEFT_MARGIN);
    if (val < 0)
        val = 0;
    uint32 c = (uint32) val;

    // 3. Limităm coloana la lungimea textului de pe ecran
    if (!visibleIndices.empty()) {
        size_t realIndex = visibleIndices[outRow]; // Mapăm vizual -> real
        const auto& line = lines[realIndex];

        size_t displayLen = line.text.length();

        // Ajustăm lungimea pentru elementele vizuale (prefixe)
        if (line.type == LineType::FileHeader) {
            displayLen += 6; // "[ ] " + " >"
        } else if (line.indentLevel > 0) {
            displayLen += 4; // indentare
        }

        if (c > displayLen)
            c = (uint32) displayLen;
    } else {
        c = 0;
    }

    outCol = c;
}
void Instance::MoveTo()
{
    // Asigură că poziția cursorului este vizibilă (Logică de Auto-Scroll)

    uint32 height         = this->GetHeight();
    uint32 width          = this->GetWidth();
    const int LEFT_MARGIN = 4;
    uint32 totalVisible = (uint32) visibleIndices.size();
    uint32 textWidth = (width > LEFT_MARGIN) ? (width - LEFT_MARGIN) : 1;

    // 1. SCROLL VERTICAL (Rânduri)
    if (this->cursorRow < this->startViewLine) {
        this->startViewLine = this->cursorRow;
    } else if (this->cursorRow >= this->startViewLine + height) {
        this->startViewLine = this->cursorRow - height + 1;
    }

    if (this->startViewLine > totalVisible)
        this->startViewLine = 0;

    // 2. SCROLL ORIZONTAL (Coloane)
    if (this->cursorCol < this->leftViewCol) {
        this->leftViewCol = this->cursorCol;
    } else if (this->cursorCol >= this->leftViewCol + textWidth) {
        this->leftViewCol = this->cursorCol - textWidth + 1;
    }
}


// Selection & Folding
void Instance::ToggleSelection()
{
    // Comută starea 'Bifat' pentru liniile de tip Header (Checkbox)
    if (this->cursorRow < yaraLines.size()) {
        if (yaraLines[this->cursorRow].type == LineType::FileHeader) {
            yaraLines[this->cursorRow].isChecked = !yaraLines[this->cursorRow].isChecked;
        }
    }
}
void Instance::SelectAllRules()
{
    // Bifează toate liniile de tip Header (Checkbox)
    bool changesMade = false;
    for (auto& line : yaraLines) {
        if (line.type == LineType::FileHeader) {
            if (!line.isChecked) {
                line.isChecked = true;
                changesMade    = true;
            }
        }
    }
}
void Instance::DeselectAllRules()
{
    // Debifează toate liniile de tip Header (Checkbox)
    bool changesMade = false;
    for (auto& line : yaraLines) {
        if (line.type == LineType::FileHeader) {
            if (line.isChecked) {
                line.isChecked = false;
                changesMade    = true;
            }
        }
    }
}
void Instance::UpdateVisibleIndices()
{
    // Reconstruiește harta vizuală (index cache) ignorând liniile ascunse
    visibleIndices.clear();
    for (size_t i = 0; i < yaraLines.size(); i++) {
        if (yaraLines[i].isVisible) {
            visibleIndices.push_back(i);
        }
    }
}
void Instance::ToggleFold(size_t index)
{
    if (index >= yaraLines.size())
        return;

    // Logică de expandare/pliere pentru secțiunile Header
    if (yaraLines[index].type == LineType::FileHeader) {

        // Inversăm starea curentă
        bool newState               = !yaraLines[index].isExpanded;
        yaraLines[index].isExpanded = newState;

        // Iterăm în jos
        for (size_t i = index + 1; i < yaraLines.size(); i++) {
            if (yaraLines[i].type == LineType::FileHeader) {
                break; // Am ajuns la următorul header, oprim
            }

            // Modificăm vizibilitatea doar pentru liniile de conținut (RuleContent)
            if (yaraLines[i].type == LineType::RuleContent) {
                yaraLines[i].isVisible = newState;
            }
        }
        // Actualizăm maparea viewport-ului
        UpdateVisibleIndices();
    }
}
void Instance::CopySelectionToClipboard()
{
    // Variabila în care vom construi textul
    std::string textToCopy;

    // Construirea textui de copiat
    {
        if (!this->selectionActive || this->yaraLines.empty())
            return;

        uint32 r1 = this->cursorRow;
        uint32 c1 = this->cursorCol;
        uint32 r2 = this->selectionAnchorRow;
        uint32 c2 = this->selectionAnchorCol;

        if (r1 > r2 || (r1 == r2 && c1 > c2)) {
            std::swap(r1, r2);
            std::swap(c1, c2);
        }

        // Iterăm prin liniile selectate
        for (uint32 r = r1; r <= r2; r++) {
            if (r >= this->yaraLines.size())
                break;

            const std::string& line = this->yaraLines[r].text;

            uint32 start = (r == r1) ? c1 : 0;
            uint32 end   = (r == r2) ? c2 : (uint32) line.length();

            if (start > line.length())
                start = (uint32) line.length();
            if (end > line.length())
                end = (uint32) line.length();

            if (end > start) {
                textToCopy += line.substr(start, end - start);
            }

            // Adăugăm NewLine dacă nu suntem la ultima linie
            if (r < r2) {
                textToCopy += "\r\n"; // Format standard Windows
            }
        }
    }

    // Trimitem datele în Clipboard-ul sistemului de operare
    if (!textToCopy.empty()) {
        AppCUI::OS::Clipboard::SetText(textToCopy);
    }
}


// Search Helpers
void Instance::SelectMatch(uint32 visualRow, size_t startRawCol, uint32 length)
{
    // 1. Identificăm linia REALĂ din maparea vizuală
    size_t realIndex = visibleIndices[visualRow];
    const auto& line = yaraLines[realIndex];

    // 2. Ajustăm coloana vizuală (compensăm indentarea sau prefixele)
    size_t visualCol = startRawCol;
    if (line.type == LineType::FileHeader)
        visualCol += 4; // "[ ] "
    else if (line.indentLevel > 0)
        visualCol += 4; // "    "

    // 3. Activăm Highlight-ul Căutării 
    this->searchActive          = true;
    this->searchResultRealIndex = realIndex; // Salvăm indexul real pentru persistență la scroll/fold
    this->searchResultStartCol  = (uint32) visualCol;
    this->searchResultLen       = length;

    // 4. Mutăm cursorul la finalul termenului găsit
    this->cursorRow = visualRow;
    this->cursorCol = (uint32) (visualCol + length);

    // Dezactivăm selecția veche pentru a evidenția doar rezultatul curent
    this->selectionActive = false;

    MoveTo(); // Asigurăm vizibilitatea cursorului
}
bool Instance::FindNext()
{
    if (lastSearchText.empty())
        return false;
    if (visibleIndices.empty() || yaraLines.empty())
        return false;

    // 1. Pregătire text (lowercase)
    std::string textToFindLower = lastSearchText;
    std::transform(textToFindLower.begin(), textToFindLower.end(), textToFindLower.begin(), ::tolower);

    uint32 totalLines = (uint32) yaraLines.size();

    // Identificăm indexul REAL al liniei unde se află cursorul
    uint32 currentRealIndex = 0;
    if (this->cursorRow < visibleIndices.size()) {
        currentRealIndex = (uint32) visibleIndices[this->cursorRow];
    }

    // --- FAZA 1: Căutăm pe restul liniei curente (de la cursor spre dreapta) ---
    {
        const auto& line      = yaraLines[currentRealIndex]; 
        std::string lineLower = line.text;
        std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(), ::tolower);

        // Calculăm offset-ul
        int searchStartOffset = this->cursorCol;
        if (line.type == LineType::FileHeader)
            searchStartOffset -= 4; // "[ ] "
        else if (line.indentLevel > 0)
            searchStartOffset -= 4; // "    "

        if (searchStartOffset < 0)
            searchStartOffset = 0;

        // Căutare efectivă
        size_t foundPos = lineLower.find(textToFindLower, searchStartOffset);

        if (foundPos != std::string::npos) {
            // Dacă am găsit, evidențiem folosind rândul vizual curent
            SelectMatch(this->cursorRow, foundPos, (uint32) textToFindLower.length());
            return true;
        }
    }

    // --- FAZA 2: Căutăm pe restul liniilor (Scanare completă cu Wrap-Around) ---
    for (uint32 i = 1; i <= totalLines; i++) {
        uint32 nextRealIdx = (currentRealIndex + i) % totalLines; // Wrap-around la început

        const auto& line      = yaraLines[nextRealIdx];
        std::string lineLower = line.text;
        std::transform(lineLower.begin(), lineLower.end(), lineLower.begin(), ::tolower);

        size_t foundPos = lineLower.find(textToFindLower); // Căutăm de la începutul liniei

        if (foundPos != std::string::npos) {
            // A. Expandăm automat secțiunea dacă linia găsită este ascunsă
            if (!line.isVisible) {
                for (int k = (int) nextRealIdx - 1; k >= 0; k--) {
                    if (yaraLines[k].type == LineType::FileHeader) {
                        if (!yaraLines[k].isExpanded)
                            ToggleFold(k);
                        break; // Am găsit părintele, ne oprim
                    }
                }
            }

            // B. Recalculăm indexul VIZUAL (poate s-a schimbat după ToggleFold)
            for (size_t v = 0; v < visibleIndices.size(); v++) {
                if (visibleIndices[v] == nextRealIdx) {
                    SelectMatch((uint32) v, foundPos, (uint32) textToFindLower.length());
                    return true;
                }
            }
        }
    }

    // Niciun rezultat găsit după o tură completă
    AppCUI::Dialogs::MessageBox::ShowNotification("Info", "No more occurrences found.");
    return false;
}


// --- Internal Logic Methods ---
void Instance::RunYara()
{
    // ---------------------------------------------------------
    // 1. SELECTIE REGULI
    // ---------------------------------------------------------
    std::vector<fs::path> selectedRules;
    for (const auto& line : yaraLines) {
        if (line.type == LineType::FileHeader && line.isChecked) {
            selectedRules.push_back(line.filePath);
        }
    }

    if (selectedRules.empty()) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "No rules selected!");
        return;
    }

    // ---------------------------------------------------------
    // 2. SETUP PATH-URI
    // ---------------------------------------------------------
    fs::path currentPath = fs::current_path();
    fs::path rootPath    = currentPath.parent_path().parent_path();
    fs::path yaraExe     = rootPath / "3rdPartyLibs" / "yara-win64" / "yara64.exe";
    fs::path outputFile  = rootPath / "3rdPartyLibs" / "output" / "output.txt";
    fs::path currentFile = this->obj->GetPath();

    fs::path outputDir = outputFile.parent_path();
    if (!fs::exists(outputDir))
        fs::create_directories(outputDir);

    if (!fs::exists(yaraExe)) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Yara exe not found!");
        return;
    }

    // ---------------------------------------------------------
    // 3. RESETARE INTERFATA
    // ---------------------------------------------------------
    this->cursorRow          = 0;
    this->cursorCol          = 0;
    this->startViewLine      = 0;
    this->leftViewCol        = 0;
    this->selectionActive    = false;
    this->selectionAnchorRow = 0;
    this->selectionAnchorCol = 0;

    yaraLines.clear();

    // Header temporar (va fi completat la final cu Summary)
    yaraLines.push_back({ "=== SCANNING RESULTS ===", LineType::Normal });
    yaraLines.push_back({ "", LineType::Normal });
    yaraLines.push_back({ "scanning...", LineType::Normal }); // Placeholder pt Summary

    int globalMatchCount = 0;

    // ---------------------------------------------------------
    // 4. EXECUTIE PER REGULA
    // ---------------------------------------------------------
    for (const auto& rulePath : selectedRules) {
        std::string ruleName = rulePath.filename().string();

        // Separator vizual între reguli
        yaraLines.push_back({ "-------------------------------------------------------------", LineType::Normal });
        yaraLines.push_back({ "Scanning with rule: " + ruleName, LineType::Info });

        // Comanda YARA
        std::string cmdArgs = "/C \"\"" + yaraExe.string() +
                              "\" -g -m -s -r "
                              "\"" +
                              rulePath.string() +
                              "\" "
                              "\"" +
                              currentFile.string() +
                              "\" "
                              "> \"" +
                              outputFile.string() + "\" 2>&1\"";

        SHELLEXECUTEINFOA shExecInfo{};
        shExecInfo.cbSize       = sizeof(SHELLEXECUTEINFOA);
        shExecInfo.fMask        = SEE_MASK_NOCLOSEPROCESS; // pentru a astepta procesul
        shExecInfo.hwnd         = nullptr;
        shExecInfo.lpVerb       = "open"; // rulare / deschide
        shExecInfo.lpFile       = "cmd.exe"; // ce se ruleaza
        shExecInfo.lpParameters = cmdArgs.c_str(); // parametrii
        shExecInfo.nShow        = SW_HIDE; // fara afisare cmd

        if (ShellExecuteExA(&shExecInfo)) {
            WaitForSingleObject(shExecInfo.hProcess, INFINITE);
            CloseHandle(shExecInfo.hProcess);

            // ---------------------------------------------------------
            // 5. PARSARE REZULTATE (Logica ta veche)
            // ---------------------------------------------------------
            std::ifstream in(outputFile);
            if (!in.is_open()) {
                yaraLines.push_back({ "    [ERROR] Cannot open output file.", LineType::Normal });
                continue;
            }

            std::string line;
            std::vector<std::string> matchedStrings;
            std::string currentRule, currentTags, currentAuthor, currentSeverity;

            bool foundAnyInFile = false;
            bool hasErrors      = false;

            while (std::getline(in, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (line.empty())
                    continue;

                foundAnyInFile = true;

                if (line.find("error:") != std::string::npos || line.find("syntax error") != std::string::npos) {
                    hasErrors          = true;
                    std::string prefix = "    [SYNTAX ERROR] ";
      
                    size_t posIn    = line.find(" in "); 
                    size_t posColon = line.find("): ");  

                    if (posIn != std::string::npos && posColon != std::string::npos) {

                        std::string partContext = line.substr(0, posIn + 3);
                        yaraLines.push_back({ prefix + partContext, LineType::Info });

                        size_t pathStart     = posIn + 4;
                        size_t pathLength    = (posColon + 2) - pathStart;
                        std::string partPath = line.substr(pathStart, pathLength);

                        yaraLines.push_back({ "        " + partPath, LineType::Info });

                        std::string partMsg = line.substr(posColon + 3);
                        yaraLines.push_back({ "        " + partMsg, LineType::Info });

                    } else {

                        std::string fullError = prefix + line;
                        const size_t MAX_LEN  = 100;

                        if (fullError.length() <= MAX_LEN) {
                            yaraLines.push_back({ fullError, LineType::Info });
                        } else {
                            size_t currentPos = 0;
                            bool isFirstLine  = true;
                            while (currentPos < fullError.length()) {
                                size_t chunkLen  = (std::min)(MAX_LEN, fullError.length() - currentPos);
                                std::string part = fullError.substr(currentPos, chunkLen);

                                if (isFirstLine) {
                                    yaraLines.push_back({ part, LineType::Info });
                                    isFirstLine = false;
                                } else {
                                    yaraLines.push_back({ "            " + part, LineType::Info });
                                }
                                currentPos += chunkLen;
                            }
                        }
                    }
                    continue;
                }

                if (line.find("warning:") != std::string::npos) {
                    std::string prefix = "    [WARNING] ";

                    size_t posIn    = line.find(" in "); // Separă regula de cale
                    size_t posColon = line.find("): ");  // Separă calea de mesaj

                    if (posIn != std::string::npos && posColon != std::string::npos) {

                        std::string partContext = line.substr(0, posIn + 3);
                        yaraLines.push_back({ prefix + partContext, LineType::Warning });

                        size_t pathStart     = posIn + 4;
                        size_t pathLength    = (posColon + 2) - pathStart;
                        std::string partPath = line.substr(pathStart, pathLength);

                        yaraLines.push_back({ "        " + partPath, LineType::Warning });

                        std::string partMsg = line.substr(posColon + 3);

                        const size_t MAX_MSG_LEN = 90;
                        if (partMsg.length() <= MAX_MSG_LEN) {
                            yaraLines.push_back({ "        " + partMsg, LineType::Warning });
                        } else {
                            size_t currentPos = 0;
                            while (currentPos < partMsg.length()) {
                                size_t chunkLen   = (std::min)(MAX_MSG_LEN, partMsg.length() - currentPos);
                                std::string chunk = partMsg.substr(currentPos, chunkLen);
                                yaraLines.push_back({ "        " + chunk, LineType::Warning });
                                currentPos += chunkLen;
                            }
                        }

                    } else {
                        std::string fullWarn = prefix + line;
                        const size_t MAX_LEN = 100;

                        size_t currentPos = 0;
                        bool isFirstLine  = true;
                        while (currentPos < fullWarn.length()) {
                            size_t chunkLen  = (std::min)(MAX_LEN, fullWarn.length() - currentPos);
                            std::string part = fullWarn.substr(currentPos, chunkLen);

                            if (isFirstLine) {
                                yaraLines.push_back({ part, LineType::Warning });
                                isFirstLine = false;
                            } else {
                                yaraLines.push_back({ "            " + part, LineType::Warning });
                            }
                            currentPos += chunkLen;
                        }
                    }
                    continue; 
                }


                if (line.find(currentFile.string()) != std::string::npos && line.find('[') != std::string::npos && line.find(']') != std::string::npos) {
                    
                    if (!currentRule.empty()) {
                        globalMatchCount++;
                        // APELĂM FUNCȚIA HELPER
                        AddMatchToUI(currentRule, currentTags, currentAuthor, currentSeverity, matchedStrings, currentFile.string());
                    }
                    

                    // === RESETARE PENTRU REGULA NOUĂ ===
                    matchedStrings.clear();
                    currentAuthor.clear();
                    currentSeverity.clear();
                    currentTags.clear();

                    // === PARSARE HEADER NOU ===
                    // 1. Rule Name
                    size_t spacePos = line.find(' ');
                    currentRule     = line.substr(0, spacePos);

                    // 2. Tags
                    size_t firstBracketStart = line.find('[');
                    size_t firstBracketEnd   = line.find(']');
                    if (firstBracketStart != std::string::npos && firstBracketEnd != std::string::npos)
                        currentTags = line.substr(firstBracketStart + 1, firstBracketEnd - firstBracketStart - 1);

                    // 3. Meta (Author, Severity)
                    size_t metaStart = line.find('[', firstBracketEnd + 1);
                    size_t metaEnd   = line.find(']', metaStart);
                    if (metaStart != std::string::npos && metaEnd != std::string::npos) {
                        std::string metaStr = line.substr(metaStart + 1, metaEnd - metaStart - 1);

                        auto extractMeta = [&](const std::string& key) -> std::string {
                            size_t keyPos = metaStr.find(key + "=\"");
                            if (keyPos != std::string::npos) {
                                size_t start = keyPos + key.length() + 2;
                                size_t end   = metaStr.find("\"", start);
                                if (end != std::string::npos)
                                    return metaStr.substr(start, end - start);
                            }
                            return "";
                        };

                        currentAuthor   = extractMeta("author");
                        currentSeverity = extractMeta("severity");
                    }
                } else {
                    // Este o linie cu un string ($s1: ...)
                    matchedStrings.push_back(line);
                }
            }
            in.close();

            // === DUMP ULTIMA REGULĂ DIN FIȘIER ===
            if (!currentRule.empty()) {
                globalMatchCount++;
                AddMatchToUI(currentRule, currentTags, currentAuthor, currentSeverity, matchedStrings, currentFile.string());
            } else if (!foundAnyInFile) {
                yaraLines.push_back({ "    [CLEAN] No matches for this rule.", LineType::Normal });
            } else if (!hasErrors && currentRule.empty()) {
                // S-a scris ceva in fisier, dar nu am detectat "error:" si nici nu am parsat o regula.
                // Poate fi Clean sau un output necunoscut.
                yaraLines.push_back({ "    [CLEAN] No matches for this rule.", LineType::Normal });
            }
        } else {
            yaraLines.push_back({ "    [ERROR] Execution failed.", LineType::Normal });
        } 
    }

    // ---------------------------------------------------------
    // 6. SUMAR FINAL (Inserat la început)
    // ---------------------------------------------------------
    // Modificăm liniile rezervate la început
    yaraLines[2].text = "Summary:";
    yaraLines.insert(yaraLines.begin() + 3, { "    Total Matches: " + std::to_string(globalMatchCount), LineType::Normal });
    yaraLines.insert(yaraLines.begin() + 4, { globalMatchCount > 0 ? "    Status: INFECTED" : "    Status: CLEAN", LineType::Normal });
    yaraLines.insert(yaraLines.begin() + 5, { "", LineType::Normal });

    yaraLines.push_back({ "=== SCAN COMPLETE ===", LineType::Normal });

    yaraExecuted      = true;
    yaraGetRulesFiles = true; // Previne reîncărcarea automată
    UpdateVisibleIndices();
}
std::string Instance::GetSectionFromOffset(const std::string& exePath, uint64_t offset)
{
    // // Deschidem fișierul EXE în modul binar
    std::ifstream file(exePath, std::ios::binary);
    if (!file)
        return "UNKNOWN";

    // 1️ DOS Header (MZ)
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    // Verificăm semnătura "MZ"
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return "NOT_A_PE";

    // 2️ Ne mutăm la offset-ul NT Headers (dat de DOS)
    file.seekg(dos.e_lfanew, std::ios::beg);
    DWORD signature = 0;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE)
        return "NOT_A_PE";


    // Citim File Header
    // Header-ul care conține numărul de secțiuni etc.
    IMAGE_FILE_HEADER fileHeader{};
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // 3️ Detect 32-bit vs 64-bit
    IMAGE_OPTIONAL_HEADER32 optional32{};
    IMAGE_OPTIONAL_HEADER64 optional64{};
    bool is64 = false;
    WORD magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(-static_cast<int>(sizeof(magic)), std::ios::cur);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        file.read(reinterpret_cast<char*>(&optional32), sizeof(optional32));
        is64 = false;

    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        file.read(reinterpret_cast<char*>(&optional64), sizeof(optional64));
        is64 = true;

    } else {
        return "UNKNOWN";
    }

    // 4️ Secțiuni
    std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);

    // iteram peste toate secțiunile
    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        file.read(reinterpret_cast<char*>(&sections[i]), sizeof(IMAGE_SECTION_HEADER));
    }

    // 5️ Căutăm secțiunea pentru offset
    for (const auto& sec : sections) {
        DWORD start = sec.PointerToRawData;
        DWORD end   = start + sec.SizeOfRawData;
        if (offset >= start && offset < end) {

            // Returnează numele secțiunii
            return std::string(reinterpret_cast<const char*>(sec.Name), strnlen(reinterpret_cast<const char*>(sec.Name), 8));
        }
    }

    return "UNKNOWN";
}
void Instance::GetRulesFiles()
{
    if (yaraGetRulesFiles)
        return;

    // ---------------------------------------------------------
    // RESETARE INTERFATA
    // ---------------------------------------------------------
    this->cursorRow          = 0;
    this->cursorCol          = 0;
    this->startViewLine      = 0;
    this->leftViewCol        = 0;
    this->selectionActive    = false;
    this->selectionAnchorRow = 0;
    this->selectionAnchorCol = 0;

    yaraLines.clear();

    fs::path currentPath = fs::current_path();
    fs::path rootPath    = currentPath.parent_path().parent_path();
    fs::path yaraRules   = rootPath / "3rdPartyLibs" / "rules";

    if (!fs::exists(yaraRules) || !fs::is_directory(yaraRules))
        return;

    // Header info
    yaraLines.push_back({ "=== YARA RULES SELECTION ===", LineType::Normal });
    yaraLines.push_back({ "", LineType::Normal });
    yaraLines.push_back({ "Controls:", LineType::Normal });
    yaraLines.push_back({ "   [Space] or [Click] : Toggle selection", LineType::Normal });
    yaraLines.push_back({ "   [Enter]            : Expand/Collapse content", LineType::Normal });
    yaraLines.push_back({ "   [Ctrl + A]         : Select All", LineType::Normal });
    yaraLines.push_back({ "   [Ctrl + D]         : Deselect All", LineType::Normal });
    yaraLines.push_back({ "   [F6] Run | [F7] View Rules | [F8] Edit", LineType::Normal });

    // --- 2. DELIMITARE ---
    yaraLines.push_back({ "_________________________________________", LineType::Normal });
    yaraLines.push_back({ "", LineType::Normal });

    // --- 3. TITLU LISTĂ ---
    yaraLines.push_back({ "Rules list:", LineType::Info }); // Folosesc Info ca să fie galben (opțional) sau Normal
    yaraLines.push_back({ "", LineType::Normal });

    for (auto& entry : fs::directory_iterator(yaraRules)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().filename().string();

            // Adăugăm HEADER-ul fișierului (care va avea checkbox)
            LineInfo header;
            header.text       = filename;
            header.type       = LineType::FileHeader;
            header.isChecked  = false;
            header.filePath   = entry.path();
            header.isExpanded = false; // <--- START PLIAT
            header.isVisible  = true;
            yaraLines.push_back(header);

            std::ifstream in(entry.path());
            if (in.is_open()) {
                std::string line;
                while (std::getline(in, line)) {
                    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                        line.pop_back();

                    // CONȚINUT (Invizibil la start)
                    LineInfo content;
                    content.text        = line;
                    content.type        = LineType::RuleContent;
                    content.isVisible   = false; // <--- ASCUNS PÂNĂ DAI ENTER
                    content.indentLevel = 1;
                    yaraLines.push_back(content);
                }
            }
            yaraLines.push_back({ "", LineType::Normal });
        }
    }
    UpdateVisibleIndices();
    yaraGetRulesFiles = true;
}
void Instance::ExportResults()
{
    // 1. Verificăm dacă avem ce salva
    if (yaraLines.empty()) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "No scan results to save!");
        return;
    }

    // 2. Dialog de confirmare salvare
    auto response = AppCUI::Dialogs::MessageBox::ShowOkCancel("Save Report", "Do you want to save the scan results to a text file?");

    if (response != Dialogs::Result::Ok) {
        return; // Dacă userul dă Cancel sau X, ieșim și nu salvăm nimic.
    }

    // 3. Generăm numele bazat pe Timestamp (Dată + Oră)
    auto now       = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d_%H-%M-%S");
    std::string fileName = "results_" + ss.str() + ".txt";

    // 4. Configurare cale output (root/3rdPartyLibs/results/) și creare folder
    fs::path currentPath = fs::current_path();
    fs::path rootPath    = currentPath.parent_path().parent_path();
    fs::path resultsDir  = rootPath / "3rdPartyLibs" / "results";

    if (!fs::exists(resultsDir)) {
        fs::create_directories(resultsDir);
    }

    fs::path fullPath = resultsDir / fileName;

    // 5. Scrierea efectivă
    std::ofstream out(fullPath);
    if (!out.is_open()) {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "Could not create file!");
        return;
    }

    for (const auto& line : yaraLines) {
        // Păstrăm indentarea
        for (int i = 0; i < line.indentLevel; i++)
            out << "\t";

        // Păstrăm checkbox-ul vizual
        if (line.type == LineType::FileHeader) {
            out << (line.isChecked ? "[x] " : "[ ] ");
        }

        out << line.text << "\n";
    }
    out.close();

    // 6. Notificare finală și deschidere folder
    AppCUI::Dialogs::MessageBox::ShowNotification("Saved", "Report saved successfully!\nOpening folder...");
    ShellExecuteA(NULL, "explore", resultsDir.string().c_str(), NULL, NULL, SW_SHOWNORMAL);
}


std::vector<std::pair<std::string, GView::View::YaraViewer::LineType>> Instance::ExtractHexContextFromYaraMatch(
      const std::string& yaraLine, const std::string& exePath, size_t contextSize)
{


    std::vector<std::pair<std::string, GView::View::YaraViewer::LineType>> output;

    // 1. Extragem offset-ul (0x....)
    size_t pos = yaraLine.find(':');
    if (pos == std::string::npos)
        return output;

    std::string offsetStr = yaraLine.substr(0, pos);
    uint64_t offset       = 0;
    try {
        // convertire în număr baza 16
        offset = std::stoull(offsetStr, nullptr, 16);
    } catch (...) {
        output.push_back({ "EROARE: Offset invalid în linia YARA.", LineType::Normal });
        return output;
    }

    // 2. Deschidem fișierul EXE in mod binar
    std::ifstream file(exePath, std::ios::binary);
    if (!file.is_open()) {
        output.push_back({ "EROARE: Nu pot deschide fișierul.", LineType::Normal });
        return output;
    }

    // 3. Calculăm zona de citire
    uint64_t startOffset = (offset > contextSize) ? offset - contextSize : 0;
    size_t readSize      = contextSize * 2;

    // mutam offsetul de citire la pozitia startOffset fata de începutul fisierului
    file.seekg(startOffset, std::ios::beg);

    // citim zona de interes în buffer
    std::vector<uint8_t> buffer(readSize);
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

    //cati bytes s-au citit efectiv (poate fi mai puțin la sfarsitul fisierului)
    size_t bytesRead = file.gcount();

    // 4. Format HEX + ASCII
    size_t lineSize = 16;
    for (size_t i = 0; i < bytesRead; i += lineSize) {
        std::ostringstream line;
        std::ostringstream ascii;

        // Construim conținutul liniei (Hex + ASCII)
        for (size_t j = 0; j < lineSize; j++) {
            if (i + j < bytesRead) {

                // luam byte-ul
                uint8_t b = buffer[i + j];

                // std::setw(2) - afișăm exact 2 caractere pentru fiecare byte
                // std::setfill('0') - dacă byte-ul are doar un caracter (A), îl completam cu 0 (0A)
                // std::hex - afișăm în hexazecimal
                // std::uppercase - litere mari (A-F)
                // static_cast<int>(b) - byte-ul convertit la int ca să nu fie interpretat ca caracter
                line << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << static_cast<int>(b) << ' ';

                //std::isprint(b) - verificare dacă byte-ul este caracter imprimabil (A-Z, 0-9, simboluri)
                ascii << (std::isprint(b) ? static_cast<char>(b) : '.');
            } else {
                line << "   ";
            }
        }

        // Construim linia completă
        std::ostringstream fullLine;
        uint64_t currentLineAddr = startOffset + i;

        fullLine << "0x" << std::setw(8) << std::setfill('0') << std::hex << currentLineAddr << "  " << line.str() << " " << ascii.str();


        // implicit linia este albă (Normala)
        GView::View::YaraViewer::LineType currentType = GView::View::YaraViewer::LineType::Normal;

        // Verificăm dacă offset-ul căutat (cel din Yara match) se află pe această linie
        // Offset-ul trebuie să fie >= începutul liniei ȘI < începutul liniei următoare
        if (offset >= currentLineAddr && offset < (currentLineAddr + lineSize)) {
            currentType = GView::View::YaraViewer::LineType::RuleContent; // RuleContent este VERDE în Paint()
        }

        // Adăugăm linia cu tipul calculat
        output.push_back({ fullLine.str(), currentType });
    }

    // 5. Header-ul cu offset (verde)
    std::ostringstream header;
    header << "File offset: 0x" << std::hex << std::uppercase << offset;

    std::ostringstream section;
    std::string sectionName = GetSectionFromOffset(exePath, offset);
    section << "Section: " << sectionName;

    // --- INSERĂM LINIILE COLORATE ---

    // Titlu (Alb)

    // Offset (Verde - folosind LineType::Info)
    output.insert(output.begin(), { header.str(), LineType::OffsetHeader });
    // Secțiune (Alb)
    output.insert(output.begin() + 1, { section.str(), LineType::Normal });

    output.insert(output.begin() + 2, { "Hex Dump:", LineType::Normal });

    return output;
}


std::vector<std::pair<std::string, GView::View::YaraViewer::LineType>> Instance::ExtractDisassemblyFromYaraMatch(
      const std::string& yaraLine, const std::string& exePath, size_t contextSize) // total bytes pentru disassembly
{
    // Returnăm perechi (Text, LineType)
    std::vector<std::pair<std::string, GView::View::YaraViewer::LineType>> output;

    // 1. Extragem offset-ul din linia YARA
    size_t pos = yaraLine.find(':');
    if (pos == std::string::npos)
        return output;

    std::string offsetStr = yaraLine.substr(0, pos);
    uint64_t offset       = 0;
    try {
        // convertire în număr baza 16
        offset = std::stoull(offsetStr, nullptr, 16);
    } catch (...) {
        output.push_back({ "EROARE: Offset invalid", LineType::Normal });
        return output;
    }

    // Sectiune valida = ".text"
    std::string section = GetSectionFromOffset(exePath, offset);
    if (section != ".text") {
        output.push_back({ "Disassembly: (skipped – non-executable section)", LineType::Normal });
        return output;
    }

    // 2. Deschidem fișierul in mod binar
    std::ifstream file(exePath, std::ios::binary);
    if (!file.is_open()) {
        output.push_back({ "EROARE: Nu pot deschide fișierul", LineType::Normal });
        return output;
    }

    // 3. Citim buffer de la offset

    // mutam offsetul de citire la pozitia startOffset fata de începutul fisierului
    file.seekg(offset, std::ios::beg);
   
    // citim zona de interes în buffer
    std::vector<uint8_t> buffer(contextSize);
    file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
   
    // cati bytes s-au citit efectiv (poate fi mai puțin la sfarsitul fisierului)
    size_t bytesRead = file.gcount();

    // ajustează mărimea vectorului exact la câți bytes am citit
    buffer.resize(bytesRead);

    if (buffer.empty()) {
        output.push_back({ "EROARE: Nu am bytes pentru disassembly", LineType::Normal });
        return output;
    }

    // 4. Capstone disassembly

    // handle sesiunee curentă
    csh handle;

    // inițializare Capstone pentru arhitectura x86 64-bit
    // CS_ARCH_X86 - arhitectura procesorului
    // CS_MODE_64 - modul 64-bit
    // Returnează CS_ERR_OK dacă inițializarea e reușită
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        output.push_back({ "EROARE: Capstone init failed", LineType::Normal });
        return output;
    }

    // CS_OPT_DETAIL, CS_OPT_OFF
    // nu vrem detalii suplimentare (precum registre folosite, flags etc.), doar instrucțiunea simplă.
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    // pointer la structurile care vor conține instrucțiunile dezasamblate
    cs_insn* insn;


    // Dezasamblăm bufferul, considerând că începe la adresa 'offset'
    // count - numărul de instrucțiuni dezasamblate
    size_t count = cs_disasm(
        handle,
        buffer.data(),  // pointer la bytes
        buffer.size(),  // câți bytes citim
        offset,         // adresă de start (pentru afișare în output)
        0,              // număr maxim de instrucțiuni (0 = toate)
        &insn           // pointer unde se scriu instrucțiunile
    );

    if (count > 0) {
        output.push_back({ "Disassembly:", LineType::Normal });

        // Iterăm prin instrucțiuni
        for (size_t i = 0; i < count; i++) {

            // insn[i]:
                // address - adresa instrucțiunii în fișier
                // mnemonic - instrucțiunea (mov, add, jmp etc.)
                // op_str - operanzii (eax, ebx, etc.)


            std::ostringstream line;
            line << "0x" << std::setw(8) << std::setfill('0') << std::hex << insn[i].address << " " << insn[i].mnemonic << " " << insn[i].op_str;

            GView::View::YaraViewer::LineType lineType = GView::View::YaraViewer::LineType::Normal;

            // dacă adresa instrucțiunii este exact offset-ul căutat -> VERDE (RuleContent)
            if (insn[i].address == offset) {
                lineType = GView::View::YaraViewer::LineType::RuleContent;
            }

            output.push_back({ line.str(), lineType });
        }
    } else {
        output.push_back({ "EROARE: Nu s-a putut disassembly", LineType::Normal });
    }

    // Curățare
    cs_free(insn, count);
    cs_close(&handle);

    return output;
}
