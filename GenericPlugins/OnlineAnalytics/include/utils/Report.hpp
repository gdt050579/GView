#pragma once

#include <string>
#include <vector>

#include "GView.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{

enum Severity : int { None = 0, Low, Medium, High, Critical };

enum AnalysisResult : int { Undetected = 0, Malicious };

struct Analysis {
    std::string engine;
    std::string version;
    AnalysisResult result;
};

struct Report {
    std::string md5;
    std::string sha1;
    std::string sha256;
    std::string fileName;
    int32 fileSize;
    std::string url;
    Severity severity;
    std::vector<std::string> capabilities;
    std::vector<Analysis> analysis;
    std::vector<std::string> tags;
};

} // namespace GView::GenericPlugins::OnlineAnalytics::Utils