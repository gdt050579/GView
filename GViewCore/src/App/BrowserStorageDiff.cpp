// Change detection of the persistent storage of the web build (BrowserStorage.cpp). Pure logic, compiled in every
// build so that it is covered by the unit tests (tests_browserstorage.cpp).

#include "Internal.hpp"

namespace GView::App::Browser::Storage
{
Changes Diff(const Snapshot& previousScan, const Snapshot& currentScan, const Snapshot& stored)
{
    Changes c;
    for (const auto& [path, stamp] : currentScan)
    {
        // a file that is still being written changes between two scans: wait until it is stable
        const auto prev = previousScan.find(path);
        if (prev == previousScan.end() || !(prev->second == stamp))
            continue;
        const auto known = stored.find(path);
        if (known == stored.end() || !(known->second == stamp))
            c.persist.push_back(path);
    }
    for (const auto& [path, stamp] : stored)
    {
        // gone in two scans in a row (a rename such as "x.part" -> "x" is not a deletion of "x")
        if (currentScan.find(path) == currentScan.end() && previousScan.find(path) == previousScan.end())
            c.remove.push_back(path);
    }
    return c;
}

bool IsStorablePath(std::string_view relativePath) noexcept
{
    if (relativePath.empty() || relativePath.size() > MAX_PATH_LENGTH || relativePath.front() == '/')
        return false;
    size_t start = 0;
    while (start <= relativePath.size())
    {
        auto end = relativePath.find('/', start);
        if (end == std::string_view::npos)
            end = relativePath.size();
        const auto part = relativePath.substr(start, end - start);
        if (part.empty() || part == "." || part == "..")
            return false;
        for (const char ch : part)
        {
            if (static_cast<unsigned char>(ch) < 0x20 || ch == 0x7F || ch == '\\')
                return false;
        }
        start = end + 1;
    }
    return true;
}
} // namespace GView::App::Browser::Storage
