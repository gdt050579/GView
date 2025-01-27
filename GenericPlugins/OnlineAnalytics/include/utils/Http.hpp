#pragma once

#include <string>

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{

struct HTTPResponse {
    std::string url;
    long status;
    std::string data;
};

struct HTTPUploadData {
    std::string name;
    const uint8_t* data;
    size_t size;
    size_t position;
};

}; // namespace GView::GenericPlugins::OnlineAnalytics::Utils