#pragma once

// Configuration of the remote TUI: the [Remote] section of gview.ini (defaults) overridden by command line options.
// Relative paths are resolved against the folder of gview.ini (portable deployments keep their certificates next to
// the binaries).

#include "RemoteServer.hpp"

#include <string>
#include <vector>

namespace GView::Remote
{
struct RemoteConfig {
    Tls::Settings tls;
    std::string bindAddress{ "127.0.0.1" };
    uint16 port{ DEFAULT_PORT };
    uint32 maxClients{ DEFAULT_MAX_CLIENTS };
};

// reads the [Remote] section of the (already loaded) settings; missing values keep their defaults
RemoteConfig LoadRemoteConfig();
// writes the default [Remote] section (used when the configuration is reset)
void WriteDefaultRemoteConfig(AppCUI::Utils::IniObject& ini);

// UI entry points (File menu)
void ShowConnectDialog();
void ShowListenDialog();
} // namespace GView::Remote
