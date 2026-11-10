#pragma once

// Small text formatting helpers shared by the Learning and Evaluation Mode windows (LearningModeWindow.cpp,
// LearningCourseDialogs.cpp). Pure, header only.

#include "Internal.hpp"

#include <cstdio>
#include <ctime>
#include <string>

namespace GView::Security::Learning
{
// "512 B", "12.3 KiB", "1.5 MiB"
inline std::string FormatSize(AppCUI::uint64 size)
{
    char buf[32];
    if (size >= 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.1f MiB", static_cast<double>(size) / (1024.0 * 1024.0));
    else if (size >= 1024)
        snprintf(buf, sizeof(buf), "%.1f KiB", static_cast<double>(size) / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long) size);
    return buf;
}

// a UNIX time in the local time zone: "2026-11-08 14:05" (empty for 0)
inline std::string FormatLocalTime(AppCUI::uint64 unixSeconds)
{
    if (unixSeconds == 0)
        return {};
    const std::time_t t = static_cast<std::time_t>(unixSeconds);
    std::tm local{};
#if defined(_WIN32)
    if (localtime_s(&local, &t) != 0)
        return {};
#else
    if (localtime_r(&t, &local) == nullptr)
        return {};
#endif
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &local) == 0)
        return {};
    return buf;
}

// a UNIX time in the local time zone, the date only: "2026-11-08" (empty for 0)
inline std::string FormatLocalDate(AppCUI::uint64 unixSeconds)
{
    const std::string full = FormatLocalTime(unixSeconds);
    return full.size() >= 10 ? full.substr(0, 10) : full;
}
} // namespace GView::Security::Learning
