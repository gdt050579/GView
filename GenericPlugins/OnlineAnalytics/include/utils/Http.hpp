#pragma once

#include <string>

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{

struct HTTPResponse {
    std::string url;
    long status;
    std::string data;
};

};