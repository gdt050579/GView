#pragma once

#include <Internal.hpp>
#include <array>

using AppCUI::uint32;
constexpr uint32 COMMAND_ADD_NEW_TYPE           = 100;
constexpr uint32 COMMAND_ADD_SHOW_FILE_CONTENT  = 101;
constexpr uint32 COMMAND_EXPORT_ASM_FILE        = 102;
constexpr uint32 COMMAND_JUMP_BACK              = 103;
constexpr uint32 COMMAND_JUMP_FORWARD           = 104;
constexpr uint32 COMMAND_DISSAM_GOTO_ENTRYPOINT = 105;
constexpr uint32 COMMAND_ADD_OR_EDIT_COMMENT    = 106;
constexpr uint32 COMMAND_REMOVE_COMMENT         = 107;
constexpr uint32 COMMAND_SHOW_ONLY_DISSASM      = 109;
constexpr uint32 COMMAND_SAVE_DISSASM_CACHE     = 110;
constexpr uint32 COMMAND_QUERY_FUNCTION_NAME    = 111;
constexpr uint32 COMMAND_QUERY_MITRE_TECHNIQUE  = 112;
constexpr uint32 COMMAND_RENAME_LABEL           = 113;
constexpr uint32 COMMAND_REMOVE_LOCAL_VARIABLE  = 114;
constexpr uint32 COMMAND_TOGGLE_NUMBER_BASE     = 115;
constexpr uint32 COMMAND_CHANGE_ADDRESS_MODE    = 116;
constexpr uint32 COMMAND_SHOW_XREFS            = 117;
constexpr uint32 COMMAND_SHOW_FUNCTIONS        = 118;
constexpr uint32 COMMAND_SHOW_STRINGS          = 119;
constexpr uint32 COMMAND_FIND_NEXT             = 120;
constexpr uint32 COMMAND_UNDO                  = 121;
constexpr uint32 COMMAND_REDO                  = 122;
constexpr uint32 COMMAND_COMMAND_PALETTE       = 123;
constexpr uint32 COMMAND_SHOW_CALL_TREE        = 124;
constexpr uint32 COMMAND_ACCEPT_AI_SUGGESTION  = 125;
constexpr uint32 COMMAND_DISMISS_AI_SUGGESTION = 126;
constexpr uint32 COMMAND_TOGGLE_AI_SUGGESTIONS = 127;
constexpr uint32 COMMAND_SUGGEST_NAMES         = 128;
constexpr uint32 COMMAND_SHOW_GRAPH            = 129;
constexpr uint32 COMMAND_GOTO_ADDRESS          = 130;
constexpr uint32 COMMAND_FIND                  = 131;
constexpr uint32 COMMAND_TOGGLE_KEY_PROFILE    = 132;
constexpr uint32 COMMAND_EXPORT_ANNOTATIONS    = 133;
constexpr uint32 COMMAND_IMPORT_ANNOTATIONS    = 134;
constexpr uint32 COMMAND_CREATE_SIGNATURES     = 135;
constexpr uint32 COMMAND_APPLY_SIGNATURES      = 136;
constexpr uint32 COMMAND_DEFINE_DATA           = 137;
constexpr uint32 COMMAND_DEFINE_STRING         = 138;
constexpr uint32 COMMAND_UNDEFINE              = 139;
constexpr uint32 COMMAND_CREATE_FUNCTION       = 140;
constexpr uint32 COMMAND_DELETE_FUNCTION       = 141;
constexpr uint32 COMMAND_TOGGLE_NORETURN       = 142;

// navigation commands (resolved through Config::Map in OnKeyEvent)
constexpr uint32 COMMAND_NAV_DOWN         = 0xC000;
constexpr uint32 COMMAND_NAV_UP           = 0xC001;
constexpr uint32 COMMAND_NAV_LEFT         = 0xC002;
constexpr uint32 COMMAND_NAV_RIGHT        = 0xC003;
constexpr uint32 COMMAND_NAV_PAGE_DOWN    = 0xC004;
constexpr uint32 COMMAND_NAV_PAGE_UP      = 0xC005;
constexpr uint32 COMMAND_NAV_HOME         = 0xC006;
constexpr uint32 COMMAND_NAV_END          = 0xC007;
constexpr uint32 COMMAND_NAV_SCROLL_UP    = 0xC008;
constexpr uint32 COMMAND_NAV_SCROLL_DOWN  = 0xC009;
constexpr uint32 COMMAND_NAV_SCROLL_LEFT  = 0xC00A;
constexpr uint32 COMMAND_NAV_SCROLL_RIGHT = 0xC00B;
constexpr uint32 COMMAND_NAV_SPACE        = 0xC00C;
constexpr uint32 COMMAND_NAV_OPEN         = 0xC00D;
constexpr uint32 COMMAND_NAV_ADD_ZONE     = 0xC00E;

using AppCUI::int32;
// TODO: reenable
constexpr int32 RIGHT_CLICK_MENU_CMD_NEW_STRUCTURE    = 0;
constexpr int32 RIGHT_CLICK_MENU_CMD_EDIT_STRUCTURE   = 1;
constexpr int32 RIGHT_CLICK_MENU_CMD_DELETE_STRUCTURE = 2;

constexpr int32 RIGHT_CLICK_MENU_CMD_NEW_COLLAPSE_ZONE                      = 3;
constexpr int32 RIGHT_CLICK_DISSASM_REMOVE_COLLAPSE_ZONE                    = 4;
constexpr int32 RIGHT_CLICK_ADD_COMMENT                                     = 5;
constexpr int32 RIGHT_CLICK_REMOVE_COMMENT                                  = 6;
constexpr int32 RIGHT_CLICK_CLEAR_SELECTION                                 = 7;
constexpr int32 RIGHT_CLICK_DISSASM_COLLAPSE_ZONE                           = 8;
constexpr int32 RIGHT_CLICK_DISSASM_EXPAND_ZONE                             = 9;
constexpr int32 RIGHT_CLICK_CODE_ZONE_EDIT                                  = 10;
constexpr int32 RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_NAME_FUNCTION           = 11;
constexpr int32 RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_EXPLAIN_CODE            = 12;
constexpr int32 RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_CONVERT_HIGH_LEVEL      = 13;
constexpr int32 RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_FN_NAME_AND_EXPLANATION = 14;
constexpr int32 RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_MITRE_TECHNIQUES        = 15;
constexpr int32 RIGHT_CLICK_DISSASM_RENAME_LOCAL_VARIABLE                   = 16;
constexpr int32 RIGHT_CLICK_DISSASM_REMOVE_LOCAL_VARIABLE                   = 17;

struct RightClickCommand {
    int commandID;
    std::string_view text;
    // Input::Key shortcutKey = Input::Key::None;
    // AppCUI::Controls::ItemHandle handle = AppCUI::Controls::InvalidItemHandle;
};

inline RightClickCommand RIGHT_CLICK_MENU_COMMANDS[] = {
    /*{ RIGHT_CLICK_MENU_CMD_NEW_STRUCTURE, "New structure" },
    { RIGHT_CLICK_MENU_CMD_EDIT_STRUCTURE, "Edit structure" },
    { RIGHT_CLICK_MENU_CMD_DELETE_STRUCTURE, "Delete structure" },*/
    { RIGHT_CLICK_CLEAR_SELECTION, "Clear selections" },
};

struct RightClickSubMenus {
    const char* name;
    std::vector<RightClickCommand> commands;
    // AppCUI::Controls::ItemHandle handle;
};

const RightClickSubMenus RIGHT_CLICK_SUB_MENUS_COMMANDS[] = {
    { "CollapsibleZone",
      { { RIGHT_CLICK_MENU_CMD_NEW_COLLAPSE_ZONE, "Add collapse zone" },
        { RIGHT_CLICK_DISSASM_REMOVE_COLLAPSE_ZONE, "Remove collapse zone" },
        { RIGHT_CLICK_DISSASM_COLLAPSE_ZONE, "Collapse zone" },
        { RIGHT_CLICK_DISSASM_EXPAND_ZONE, "Expand zone" } } },
    { "Comment", { { RIGHT_CLICK_ADD_COMMENT, "Add comment" }, { RIGHT_CLICK_REMOVE_COMMENT, "Remove comment" } } },
    { "LocalVariable",
      { { RIGHT_CLICK_DISSASM_RENAME_LOCAL_VARIABLE, "Rename local variable" }, { RIGHT_CLICK_DISSASM_REMOVE_LOCAL_VARIABLE, "Remove local variable" } } },
    { "CodeZone", { { RIGHT_CLICK_CODE_ZONE_EDIT, "Edit zone" } } },
    { "Assistant",
      {
            { RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_NAME_FUNCTION, "Ask appropriate name function" },
            { RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_EXPLAIN_CODE, "Explain the code in selection" },
            { RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_CONVERT_HIGH_LEVEL, "Convert selection code to a higher form" },
            { RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_FN_NAME_AND_EXPLANATION, "Ask for name and small explanation" },
            { RIGHT_CLICK_DISSASM_ASSISTANT_QUERY_MITRE_TECHNIQUES, "Ask for MITRE techniques" },
      } }
};

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        using namespace AppCUI;

        struct DissasmColors {
            Graphics::ColorPair Normal;
            Graphics::ColorPair Highlight;
            Graphics::ColorPair HighlightCursorLine;
            Graphics::ColorPair Inactive;
            Graphics::ColorPair Cursor;
            Graphics::ColorPair Line;
            Graphics::ColorPair Selection;
            //Graphics::ColorPair OutsideZone;
            Graphics::ColorPair StructureColor; // struct definitions
            Graphics::ColorPair DataTypeColor;
            Graphics::ColorPair AsmOffsetColor;                // 0x something
            Graphics::ColorPair AsmIrrelevantInstructionColor; // int3
            Graphics::ColorPair AsmWorkRegisterColor;          // eax, ebx, ecx, edx
            Graphics::ColorPair AsmStackRegisterColor;         // ebp, edi, esi
            Graphics::ColorPair AsmCompareInstructionColor;    // test, cmp
            Graphics::ColorPair AsmFunctionColor;              // ret call
            Graphics::ColorPair AsmLocationInstruction;        // dword ptr[ ]
            Graphics::ColorPair AsmJumpInstruction;            // jmp
            Graphics::ColorPair AsmSystemInstructionColor;     // syscall, int, cpuid, rdtsc, sidt: system / anti debug instructions
            Graphics::ColorPair AsmComment;                    // comments added by user
            Graphics::ColorPair AsmLocalVariableColor;         // var_8, arg_0
            Graphics::ColorPair AsmDefaultColor;               // rest of things
            Graphics::ColorPair AsmTitleColor;
            Graphics::ColorPair AsmTitleColumnColor;

            Graphics::ColorPair CursorNormal, CursorLine, CursorHighlighted;
            bool hasChanges = false;
        };

        struct ColorManager {
            DissasmColors Colors;
            DissasmColors SavedColors;

            void InitFromConfigColors(const DissasmColors& configColors, bool hasFocus);
            void OnLostFocus();
            void SetAllColorsInactive();
            void OnGainedFocus();
        };

        struct Config : public Dialogs::OnThemePreviewWindowDrawInterface, public Dialogs::OnThemeChangedInterface {
            DissasmColors ConfigColors;

            // TODO: reenable when the functionality is implemented
            //  Command Bar keys
            // inline static DissasmCommand AddNewTypeCommand            = { Input::Key::F6, "AddNewType", "Add new data type", COMMAND_ADD_NEW_TYPE };
            inline static KeyboardControl ShowOnlyDissasmCommand = {
                Input::Key::F7, "ShowOnlyDissasm", "Show only the dissasm code", COMMAND_SHOW_ONLY_DISSASM
            };
            // inline static DissasmCommand ShowOrHideFileContentCommand = {
            //     Input::Key::F9, "ShowOrHideFileContent", "Show or hide file content", COMMAND_ADD_SHOW_FILE_CONTENT
            // };
            inline static KeyboardControl AsmExportFileContentCommand = {
                Input::Key::F8, "AsmExportToFile", "Export ASM content to file", COMMAND_EXPORT_ASM_FILE
            };
            inline static KeyboardControl JumpBackCommand    = { Input::Key::Ctrl | Input::Key::Q, "JumpBack", "Jump to previous location", COMMAND_JUMP_BACK };
            inline static KeyboardControl JumpForwardCommand = {
                Input::Key::Ctrl | Input::Key::E, "JumpForward", "Jump to a forward location", COMMAND_JUMP_FORWARD
            };
            inline static KeyboardControl GotoEntrypointCommand = {
                Input::Key::F2, "GoToEntrypoint", "Go to the entry point of the dissasm zone", COMMAND_DISSAM_GOTO_ENTRYPOINT
            };

            // the same key and name as the address mode of the buffer view
            inline static KeyboardControl ChangeAddressModeCommand = {
                Input::Key::F3, "ChangeAddressMode", "Show the addresses as VA, RVA or file offsets", COMMAND_CHANGE_ADDRESS_MODE
            };

            inline static KeyboardControl UndoCommand = { Input::Key::Ctrl | Input::Key::Z, "Undo", "Undo the last edit (comment, rename, numbers base, zone)", COMMAND_UNDO };
            inline static KeyboardControl RedoCommand = { Input::Key::Ctrl | Input::Key::Y, "Redo", "Redo the last undone edit", COMMAND_REDO };
            inline static KeyboardControl CommandPaletteCommand = {
                Input::Key::Ctrl | Input::Key::P, "CommandPalette", "Show every command of the view with its key", COMMAND_COMMAND_PALETTE
            };

            inline static KeyboardControl ToggleAISuggestionsCommand = {
                Input::Key::Ctrl | Input::Key::Shift | Input::Key::A, "ToggleAISuggestions", "Show or hide the suggestions of the assistant (comments, names)", COMMAND_TOGGLE_AI_SUGGESTIONS
            };
            inline static KeyboardControl SuggestNamesCommand = { Input::Key::Ctrl | Input::Key::Shift | Input::Key::K,
                                                                  "SuggestFunctionNames",
                                                                  "Ask the assistant names for the current function and the functions it calls",
                                                                  COMMAND_SUGGEST_NAMES };

            // the key profiles: the keys of GView, or the ones of IDA (G, X, ; / :, Esc, Ctrl+Enter, Enter, Space, Alt+T, Ctrl+T); the user's
            // keys ([Keys.View.Dissasm]) win over both
            enum class KeyProfile : uint8 { Default, IDA };
            inline static KeyProfile ActiveKeyProfile = KeyProfile::Default;
            inline static KeyboardControl GoToAddressCommand = {
                Input::Key::None, "GoToAddress", "Go to an address or a label name (the IDA profile: G; both: F5 of the window)", COMMAND_GOTO_ADDRESS
            };
            inline static KeyboardControl FindCommand = {
                Input::Key::None, "Find", "Find a text, bytes or an immediate value (the IDA profile: Alt+T; both: Ctrl+F of the window)", COMMAND_FIND
            };
            inline static KeyboardControl ToggleKeyProfileCommand = { Input::Key::Ctrl | Input::Key::Shift | Input::Key::P,
                                                                      "ToggleKeyProfile",
                                                                      "Switch the keys between the GView and the IDA profiles (saved in GView.ini)",
                                                                      COMMAND_TOGGLE_KEY_PROFILE };

            inline static KeyboardControl ExportAnnotationsCommand = {
                Input::Key::None, "ExportAnnotations", "Write the names, comments, variables and zones to a JSON file (by address)", COMMAND_EXPORT_ANNOTATIONS
            };
            inline static KeyboardControl ImportAnnotationsCommand = {
                Input::Key::None, "ImportAnnotations", "Add the names, comments, variables and zones of a JSON annotations file", COMMAND_IMPORT_ANNOTATIONS
            };
            inline static KeyboardControl CreateSignaturesCommand = {
                Input::Key::None, "CreateSignatures", "Write the signatures of the named functions to a JSON file (FLIRT like)", COMMAND_CREATE_SIGNATURES
            };
            inline static KeyboardControl ApplySignaturesCommand = {
                Input::Key::None, "ApplySignatures", "Name the sub_ functions that match a JSON signatures file", COMMAND_APPLY_SIGNATURES
            };

            inline static KeyboardControl ShowGraphCommand = {
                Input::Key::Ctrl | Input::Key::B, "ShowGraph", "Show the graph of the basic blocks of the current function", COMMAND_SHOW_GRAPH
            };

            inline static KeyboardControl ShowCallTreeCommand = {
                Input::Key::Ctrl | Input::Key::R, "ShowCallTree", "Show the callers and the callees of the current function", COMMAND_SHOW_CALL_TREE
            };

            inline static KeyboardControl ShowStringsCommand = {
                Input::Key::Shift | Input::Key::F12, "ShowStrings", "Show the strings used by the code", COMMAND_SHOW_STRINGS
            };
            inline static KeyboardControl FindNextCommand = { Input::Key::F6, "FindNext", "Find the next match of the last search", COMMAND_FIND_NEXT };

            inline static KeyboardControl ShowFunctionsCommand = {
                Input::Key::Shift | Input::Key::F3, "ShowFunctions", "Show the functions found by the analysis", COMMAND_SHOW_FUNCTIONS
            };

            inline static KeyboardControl ShowXrefsCommand = {
                Input::Key::Ctrl | Input::Key::X, "ShowXrefs", "Show the cross references to the label / target of the line", COMMAND_SHOW_XREFS
            };

            inline static KeyboardControl CommandQueryFunctionName = {
                Input::Key::Ctrl | Input::Key::K, "QueryFunctionName", "Query Digital Assistants (if any) for function name", COMMAND_QUERY_FUNCTION_NAME
            };

            inline static KeyboardControl CommandQueryMITRETechnique = {
                Input::Key::Ctrl | Input::Key::L, "QueryMITRETechnique", "Query Digital Assistants (if any) for MITRE Techniques", COMMAND_QUERY_MITRE_TECHNIQUE
            };

            inline static std::array<std::reference_wrapper<KeyboardControl>, 22> CommandBarCommands = {
                /*AddNewTypeCommand,*/ ChangeAddressModeCommand,
                GoToAddressCommand,
                FindCommand,
                ToggleKeyProfileCommand,
                ShowGraphCommand,
                ToggleAISuggestionsCommand,
                SuggestNamesCommand,
                ShowCallTreeCommand,
                UndoCommand,
                RedoCommand,
                CommandPaletteCommand,
                ShowXrefsCommand,
                ShowFunctionsCommand,
                ShowStringsCommand,
                FindNextCommand,
                ShowOnlyDissasmCommand, /*ShowOrHideFileContentCommand,*/
                AsmExportFileContentCommand,
                JumpBackCommand,
                JumpForwardCommand,
                GotoEntrypointCommand,
                CommandQueryFunctionName,
                CommandQueryMITRETechnique
            };

            // Other keys
            inline static KeyboardControl AcceptAISuggestionCommand = {
                Input::Key::A, "AcceptAISuggestion", "Accept the suggestion of the assistant on the line (name / comment)", COMMAND_ACCEPT_AI_SUGGESTION
            };
            inline static KeyboardControl DismissAISuggestionCommand = {
                Input::Key::Shift | Input::Key::A, "DismissAISuggestion", "Dismiss the suggestion of the assistant on the line", COMMAND_DISMISS_AI_SUGGESTION
            };
            inline static KeyboardControl AddOrEditCommentCommand = { Input::Key::C, "AddOrEditComment", "Add or edit comments", COMMAND_ADD_OR_EDIT_COMMENT };
            inline static KeyboardControl RemoveCommentCommand    = { Input::Key::Delete, "RemoveComment", "Remove comment", COMMAND_REMOVE_COMMENT };
            inline static KeyboardControl RenameLabelCommand      = {
                Input::Key::N, "RenameLabel", "Rename label, function or local variable", COMMAND_RENAME_LABEL
            };
            inline static KeyboardControl RemoveLocalVariableCommand = { Input::Key::Shift | Input::Key::Delete,
                                                                         "RemoveLocalVariable",
                                                                         "Remove the local variable defined or used on the current line",
                                                                         COMMAND_REMOVE_LOCAL_VARIABLE };
            inline static KeyboardControl SaveCacheCommand        = {
                Input::Key::Ctrl | Input::Key::S, "SaveCache", "Save dissasm cache (will automatically save on ESCAPE)", COMMAND_SAVE_DISSASM_CACHE
            };
            inline static KeyboardControl ToggleNumberBaseCommand = {
                Input::Key::H, "ToggleNumberBase", "Show the number under the cursor in decimal / hexadecimal", COMMAND_TOGGLE_NUMBER_BASE
            };
            inline static KeyboardControl DefineDataCommand = {
                Input::Key::D, "DefineData", "Make the bytes of the line data (again: db, dw, dd, dq)", COMMAND_DEFINE_DATA
            };
            inline static KeyboardControl DefineStringCommand = {
                Input::Key::Shift | Input::Key::D, "DefineString", "Make the line a string (the ASCII text up to its zero)", COMMAND_DEFINE_STRING
            };
            inline static KeyboardControl UndefineCommand = {
                Input::Key::U, "Undefine", "Remove the data / string of the line (decoded as code again)", COMMAND_UNDEFINE
            };
            // IDA P / Delete function / Alt+P (the attributes of the function)
            inline static KeyboardControl CreateFunctionCommand = {
                Input::Key::P, "CreateFunction", "Make the line the start of a function", COMMAND_CREATE_FUNCTION
            };
            inline static KeyboardControl DeleteFunctionCommand = {
                Input::Key::Shift | Input::Key::P, "DeleteFunction", "The function of the line is not a function any more (its label stays)", COMMAND_DELETE_FUNCTION
            };
            inline static KeyboardControl ToggleNoReturnCommand = {
                Input::Key::Alt | Input::Key::P, "ToggleNoReturn", "Mark the function of the line as one that does not return (again: it returns)", COMMAND_TOGGLE_NORETURN
            };

            inline static std::array<std::reference_wrapper<KeyboardControl>, 4> KeyDownCommands = {
                AddOrEditCommentCommand, RemoveCommentCommand, RenameLabelCommand, RemoveLocalVariableCommand
            };

            // navigation & editing
            using KF = KeyboardControlFlags;
            inline static KeyboardControl MoveDownCommand  = { Input::Key::Down, "MoveDown", "Move one line down", COMMAND_NAV_DOWN, KF::ShiftExtendsSelection };
            inline static KeyboardControl MoveUpCommand    = { Input::Key::Up, "MoveUp", "Move one line up", COMMAND_NAV_UP, KF::ShiftExtendsSelection };
            inline static KeyboardControl MoveLeftCommand  = { Input::Key::Left, "MoveLeft", "Move one character to the left", COMMAND_NAV_LEFT, KF::ShiftExtendsSelection };
            inline static KeyboardControl MoveRightCommand = {
                Input::Key::Right, "MoveRight", "Move one character to the right", COMMAND_NAV_RIGHT, KF::ShiftExtendsSelection
            };
            inline static KeyboardControl MovePageDownCommand = { Input::Key::PageDown, "MovePageDown", "Move one page down", COMMAND_NAV_PAGE_DOWN, KF::ShiftExtendsSelection };
            inline static KeyboardControl MovePageUpCommand   = { Input::Key::PageUp, "MovePageUp", "Move one page up", COMMAND_NAV_PAGE_UP, KF::ShiftExtendsSelection };
            inline static KeyboardControl MoveHomeCommand     = { Input::Key::Home, "MoveToLineStart", "Move to the start of the line", COMMAND_NAV_HOME, KF::ShiftExtendsSelection };
            inline static KeyboardControl MoveEndCommand      = { Input::Key::End, "MoveToLineEnd", "Move to the end of the line", COMMAND_NAV_END, KF::ShiftExtendsSelection };
            inline static KeyboardControl ScrollUpCommand     = { Input::Key::Ctrl | Input::Key::Up, "ScrollUp", "Scroll the view one line up", COMMAND_NAV_SCROLL_UP };
            inline static KeyboardControl ScrollDownCommand   = { Input::Key::Ctrl | Input::Key::Down, "ScrollDown", "Scroll the view one line down", COMMAND_NAV_SCROLL_DOWN };
            inline static KeyboardControl ScrollLeftCommand   = { Input::Key::Ctrl | Input::Key::Left, "ScrollLeft", "Scroll the view to the left", COMMAND_NAV_SCROLL_LEFT };
            inline static KeyboardControl ScrollRightCommand  = { Input::Key::Ctrl | Input::Key::Right, "ScrollRight", "Scroll the view to the right", COMMAND_NAV_SCROLL_RIGHT };
            inline static KeyboardControl SpaceCommand        = {
                Input::Key::Space, "ExpandOrFollow", "Expand / collapse the current zone or follow the current call / jump", COMMAND_NAV_SPACE
            };
            inline static KeyboardControl OpenSelectionCommand = { Input::Key::Enter, "OpenSelection", "Open the current selection as a new object", COMMAND_NAV_OPEN };
            inline static KeyboardControl AddZoneCommand       = { Input::Key::X, "AddCollapsibleZone", "Add a collapsible zone over the selection", COMMAND_NAV_ADD_ZONE };

            inline static std::array<KeyboardControl*, 15> NavigationCommands = {
                &MoveDownCommand,   &MoveUpCommand,     &MoveLeftCommand,    &MoveRightCommand,     &MovePageDownCommand,
                &MovePageUpCommand, &MoveHomeCommand,   &MoveEndCommand,     &ScrollUpCommand,      &ScrollDownCommand,
                &ScrollLeftCommand, &ScrollRightCommand, &SpaceCommand,      &OpenSelectionCommand, &AddZoneCommand,
            };
            // keys handled in OnKeyEvent (navigation + the editing keys)
            inline static std::array<KeyboardControl*, 29> KeyEventCommands = {
                &AcceptAISuggestionCommand,
                &DismissAISuggestionCommand,
                &MoveDownCommand,
                &MoveUpCommand,
                &MoveLeftCommand,
                &MoveRightCommand,
                &MovePageDownCommand,
                &MovePageUpCommand,
                &MoveHomeCommand,
                &MoveEndCommand,
                &ScrollUpCommand,
                &ScrollDownCommand,
                &ScrollLeftCommand,
                &ScrollRightCommand,
                &SpaceCommand,
                &OpenSelectionCommand,
                &AddZoneCommand,
                &AddOrEditCommentCommand,
                &RemoveCommentCommand,
                &RenameLabelCommand,
                &RemoveLocalVariableCommand,
                &SaveCacheCommand,
                &ToggleNumberBaseCommand,
                &DefineDataCommand,
                &DefineStringCommand,
                &UndefineCommand,
                &CreateFunctionCommand,
                &DeleteFunctionCommand,
                &ToggleNoReturnCommand,
            };
            inline static Input::KeyMap Map;

            inline static std::array<std::reference_wrapper<KeyboardControl>, 32> AllKeyboardCommands = {
                /*AddNewTypeCommand,*/ ChangeAddressModeCommand,
                ExportAnnotationsCommand,
                ImportAnnotationsCommand,
                CreateSignaturesCommand,
                ApplySignaturesCommand,
                GoToAddressCommand,
                FindCommand,
                ToggleKeyProfileCommand,
                ShowGraphCommand,
                ToggleAISuggestionsCommand,
                SuggestNamesCommand,
                ShowCallTreeCommand,
                UndoCommand,
                RedoCommand,
                CommandPaletteCommand,
                ShowXrefsCommand,
                ShowFunctionsCommand,
                ShowStringsCommand,
                FindNextCommand,
                ShowOnlyDissasmCommand,
                /*ShowOrHideFileContentCommand,*/ AsmExportFileContentCommand,
                JumpBackCommand,
                JumpForwardCommand,
                GotoEntrypointCommand,
                AddOrEditCommentCommand,
                RemoveCommentCommand,
                RenameLabelCommand,
                RemoveLocalVariableCommand,
                SaveCacheCommand,
                ToggleNumberBaseCommand,
                CommandQueryFunctionName,
                CommandQueryMITRETechnique
            };
            bool Loaded;

            bool ShowFileContent;
            bool ShowOnlyDissasm;
            // the addresses of the instructions (the labels are always named after the VA): VA, RVA or file offset (DissasmPEConversionType)
            uint8 AddressMode = 2;
            bool EnableDeepScanDissasmOnStart;
            bool CacheSameLocationAsAnalyzedFile;
            bool AlignPadding = true; // the padding between the functions (int3, nop) is one line: align 0x10
            static void Update(AppCUI::Utils::IniSection sect);
            void UpdateColors(const AppCUI::Application::Config& config);
            void Initialize(const AppCUI::Application::Config& config);

            ~Config() override;
            void OnPreviewWindowDraw(
                  std::string_view categoryName,
                  Graphics::Renderer& r,
                  int startingX,
                  int startingY,
                  Graphics::Size sz,
                  const Application::Config::CustomColorNameStorage& colors) override;
            void OnThemeChanged(const Application::Config& config) override;
        };

        void ApplyKeyProfile(Config::KeyProfile profile);
        Config::KeyProfile ReadKeyProfile();
        void RegisterKeys(KeyboardControlsInterface* interface);
        void OnKeysChanged();
    } // namespace DissasmViewer
} // namespace View
} // namespace GView