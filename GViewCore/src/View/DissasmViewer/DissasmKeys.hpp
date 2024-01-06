#pragma once

#include <AppCUI/include/AppCUI.hpp>
using AppCUI::uint32;
constexpr uint32 COMMAND_ADD_NEW_TYPE           = 100;
constexpr uint32 COMMAND_ADD_SHOW_FILE_CONTENT  = 101;
constexpr uint32 COMMAND_EXPORT_ASM_FILE        = 102;
constexpr uint32 COMMAND_JUMP_BACK              = 103;
constexpr uint32 COMMAND_JUMP_FORWARD           = 104;
constexpr uint32 COMMAND_DISSAM_GOTO_ENTRYPOINT = 105;

using AppCUI::int32;
//TODO: reenable
constexpr int32 RIGHT_CLICK_MENU_CMD_NEW        = 0;
constexpr int32 RIGHT_CLICK_MENU_CMD_EDIT       = 1;
constexpr int32 RIGHT_CLICK_MENU_CMD_DELETE     = 2;

constexpr int32 RIGHT_CLICK_MENU_CMD_COLLAPSE   = 3;
constexpr int32 RIGHT_CLICK_ADD_COMMENT         = 4;
constexpr int32 RIGHT_CLICK_REMOVE_COMMENT      = 5;
constexpr int32 RIGHT_CLICK_DISSASM_ADD_ZONE    = 6;
constexpr int32 RIGHT_CLICK_DISSASM_REMOVE_ZONE = 7;
