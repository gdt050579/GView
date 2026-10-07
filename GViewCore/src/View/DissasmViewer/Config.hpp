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

            inline static KeyboardControl CommandQueryFunctionName = {
                Input::Key::Ctrl | Input::Key::K, "QueryFunctionName", "Query Digital Assistants (if any) for function name", COMMAND_QUERY_FUNCTION_NAME
            };

            inline static KeyboardControl CommandQueryMITRETechnique = {
                Input::Key::Ctrl | Input::Key::L, "QueryMITRETechnique", "Query Digital Assistants (if any) for MITRE Techniques", COMMAND_QUERY_MITRE_TECHNIQUE
            };

            inline static std::array<std::reference_wrapper<KeyboardControl>, 7> CommandBarCommands = {
                /*AddNewTypeCommand,*/ ShowOnlyDissasmCommand, /*ShowOrHideFileContentCommand,*/
                AsmExportFileContentCommand,
                JumpBackCommand,
                JumpForwardCommand,
                GotoEntrypointCommand,
                CommandQueryFunctionName,
                CommandQueryMITRETechnique
            };

            // Other keys
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
            inline static std::array<KeyboardControl*, 20> KeyEventCommands = {
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
            };
            inline static Input::KeyMap Map;

            inline static std::array<std::reference_wrapper<KeyboardControl>, 12> AllKeyboardCommands = {
                /*AddNewTypeCommand,*/ ShowOnlyDissasmCommand,
                /*ShowOrHideFileContentCommand,*/ AsmExportFileContentCommand,
                JumpBackCommand,
                JumpForwardCommand,
                GotoEntrypointCommand,
                AddOrEditCommentCommand,
                RemoveCommentCommand,
                RenameLabelCommand,
                RemoveLocalVariableCommand,
                SaveCacheCommand,
                CommandQueryFunctionName,
                CommandQueryMITRETechnique
            };
            bool Loaded;

            bool ShowFileContent;
            bool ShowOnlyDissasm;
            bool EnableDeepScanDissasmOnStart;
            bool CacheSameLocationAsAnalyzedFile;
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

        void RegisterKeys(KeyboardControlsInterface* interface);
        void OnKeysChanged();
    } // namespace DissasmViewer
} // namespace View
} // namespace GView