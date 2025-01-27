#include <format>
#include "utils/Visit.hpp"

namespace GView::GenericPlugins::OnlineAnalytics::Utils
{

/*
 * Solution found here: https://stackoverflow.com/a/76964675
 */
void VisitUrl(std::string& url)
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    std::system(std::format("start {}", url).c_str());
#elif __APPLE__
    std::system(std::format("open {}", url).c_str());
#elif __linux__
    std::system(std::format("xdg-open {}", url).c_str());
#else
#    error "Unknown compiler"
#endif
}

} // namespace GView::GenericPlugins::OnlineAnalytics::Utils