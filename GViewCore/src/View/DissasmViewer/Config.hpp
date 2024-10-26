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
constexpr uint32 COMMAND_AVAILABLE_KEYS         = 108;
constexpr uint32 COMMAND_SHOW_ONLY_DISSASM      = 109;

using AppCUI::int32;
// TODO: reenable
constexpr int32 RIGHT_CLICK_MENU_CMD_NEW_STRUCTURE    = 0;
constexpr int32 RIGHT_CLICK_MENU_CMD_EDIT_STRUCTURE   = 1;
constexpr int32 RIGHT_CLICK_MENU_CMD_DELETE_STRUCTURE = 2;

constexpr int32 RIGHT_CLICK_MENU_CMD_NEW_COLLAPSE_ZONE   = 3;
constexpr int32 RIGHT_CLICK_DISSASM_REMOVE_COLLAPSE_ZONE = 4;
constexpr int32 RIGHT_CLICK_ADD_COMMENT                  = 5;
constexpr int32 RIGHT_CLICK_REMOVE_COMMENT               = 6;
constexpr int32 RIGHT_CLICK_CLEAR_SELECTION              = 7;
constexpr int32 RIGHT_CLICK_DISSASM_COLLAPSE_ZONE        = 8;
constexpr int32 RIGHT_CLICK_DISSASM_EXPAND_ZONE          = 9;

constexpr int32 RIGHT_CLICK_CODE_ZONE_EDIT = 10;

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
      {
            { RIGHT_CLICK_MENU_CMD_NEW_COLLAPSE_ZONE, "Add collapse zone" },
            { RIGHT_CLICK_DISSASM_REMOVE_COLLAPSE_ZONE, "Remove collapse zone" },
            { RIGHT_CLICK_DISSASM_COLLAPSE_ZONE, "Collapse zone" },
            { RIGHT_CLICK_DISSASM_EXPAND_ZONE, "Expand zone" }
      } },
    { "Comment", { { RIGHT_CLICK_ADD_COMMENT, "Add comment" }, { RIGHT_CLICK_REMOVE_COMMENT, "Remove comment" } } },
    { "CodeZone", { { RIGHT_CLICK_CODE_ZONE_EDIT, "Edit zone" } } }
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
            Graphics::ColorPair OutsideZone;
            Graphics::ColorPair StructureColor;
            Graphics::ColorPair DataTypeColor;
            Graphics::ColorPair AsmOffsetColor;                // 0x something
            Graphics::ColorPair AsmIrrelevantInstructionColor; // int3
            Graphics::ColorPair AsmWorkRegisterColor;          // eax, ebx,ecx, edx
            Graphics::ColorPair AsmStackRegisterColor;         // ebp, edi, esi
            Graphics::ColorPair AsmCompareInstructionColor;    // test, cmp
            Graphics::ColorPair AsmFunctionColor;              // ret call
            Graphics::ColorPair AsmLocationInstruction;        // dword ptr[ ]
            Graphics::ColorPair AsmJumpInstruction;            // jmp
            Graphics::ColorPair AsmComment;                    // comments added by user
            Graphics::ColorPair AsmDefaultColor;               // rest of things
            Graphics::ColorPair AsmTitleColor;
            Graphics::ColorPair AsmTitleColumnColor;

            Graphics::ColorPair CursorNormal, CursorLine, CursorHighlighted;
        };

        struct ColorManager {
            DissasmColors Colors;
            DissasmColors SavedColors;

            void InitFromConfigColors(DissasmColors& configColors);
            void OnLostFocus();
            void SetAllColorsInactive();
            void OnGainedFocus();
        };

        struct Config {
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
            inline static KeyboardControl JumpBackCommand   = { Input::Key::Ctrl | Input::Key::Q, "JumpBack", "Jump to previous location", COMMAND_JUMP_BACK };
            inline static KeyboardControl JumpForwardCommand = {
                Input::Key::Ctrl | Input::Key::E, "JumpForward", "Jump to a forward location", COMMAND_JUMP_FORWARD
            };
            inline static KeyboardControl GotoEntrypointCommand = {
                Input::Key::F2, "GoToEntrypoint", "Go to the entry point of the dissasm zone", COMMAND_DISSAM_GOTO_ENTRYPOINT
            };
            inline static KeyboardControl ShowKeysWindowCommand = { Input::Key::F1, "ShowKeys", "Show available keys in dissasm", COMMAND_AVAILABLE_KEYS };

            inline static std::array<std::reference_wrapper<KeyboardControl>, 6> CommandBarCommands = {
                /*AddNewTypeCommand,*/ ShowOnlyDissasmCommand, /*ShowOrHideFileContentCommand,*/
                AsmExportFileContentCommand,
                JumpBackCommand,
                JumpForwardCommand,
                GotoEntrypointCommand,
                ShowKeysWindowCommand
            };

            // Other keys
            inline static KeyboardControl AddOrEditCommentCommand = { Input::Key::C, "AddOrEditComment", "Add or edit comments", COMMAND_ADD_OR_EDIT_COMMENT };
            inline static KeyboardControl RemoveCommentCommand    = { Input::Key::Delete, "RemoveComment", "Remove comment", COMMAND_REMOVE_COMMENT };
            inline static KeyboardControl RenameLabelCommand      = { Input::Key::N, "RenameLabel", "Rename label or function", COMMAND_REMOVE_COMMENT };

            inline static std::array<std::reference_wrapper<KeyboardControl>, 3> KeyDownCommands = { AddOrEditCommentCommand,
                                                                                                    RemoveCommentCommand,
                                                                                                    RenameLabelCommand };

            inline static std::array<std::reference_wrapper<KeyboardControl>, 9> AllKeyboardCommands = {
                /*AddNewTypeCommand,*/ ShowOnlyDissasmCommand,
                /*ShowOrHideFileContentCommand,*/ AsmExportFileContentCommand,
                JumpBackCommand,
                JumpForwardCommand,
                GotoEntrypointCommand,
                AddOrEditCommentCommand,
                RemoveCommentCommand,
                ShowKeysWindowCommand,
                RenameLabelCommand
            };
            bool Loaded;

            bool ShowFileContent;
            bool ShowOnlyDissasm;
            bool EnableDeepScanDissasmOnStart;
            bool CacheSameLocationAsAnalyzedFile;
            static void Update(AppCUI::Utils::IniSection sect);
            void Initialize();
        };

        class KeyConfigDisplayWindow : public Controls::Window
        {
          public:
            KeyConfigDisplayWindow();
            virtual bool OnEvent(AppCUI::Utils::Reference<Control>, AppCUI::Controls::Event eventType, int ID) override;
        };
    } // namespace DissasmViewer
} // namespace View
} // namespace GView