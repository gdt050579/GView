// GViewUpdater - applies an update staged by GView. Started by GView itself after its UI has closed:
//   GViewUpdater apply --staging <dir> --target <dir> --old <dir> [--log <file>]
// Exit codes: see Apply.hpp.

#include "Apply.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

namespace
{
template <typename CharT>
bool Equals(const CharT* arg, const char* ascii)
{
    while (*arg && *ascii) {
        if (static_cast<char32_t>(*arg) != static_cast<char32_t>(static_cast<unsigned char>(*ascii)))
            return false;
        arg++;
        ascii++;
    }
    return *arg == 0 && *ascii == 0;
}

void Usage()
{
    std::printf("Use: GViewUpdater apply --staging <dir> --target <dir> --old <dir> [--log <file>]\n"
                "This program is started by GView to install an update; it is not meant to be run manually.\n");
}

template <typename CharT>
int Run(int argc, const CharT** argv)
{
    if (argc < 2 || !Equals(argv[1], "apply")) {
        Usage();
        return GViewUpdater::EXIT_USAGE;
    }
    GViewUpdater::Options options;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) {
            Usage();
            return GViewUpdater::EXIT_USAGE;
        }
        const std::filesystem::path value(argv[i + 1]);
        if (Equals(argv[i], "--staging"))
            options.staging = value;
        else if (Equals(argv[i], "--target"))
            options.target = value;
        else if (Equals(argv[i], "--old"))
            options.old = value;
        else if (Equals(argv[i], "--log"))
            options.log = value;
        else {
            Usage();
            return GViewUpdater::EXIT_USAGE;
        }
    }
    if (options.staging.empty() || options.target.empty() || options.old.empty() || !options.staging.is_absolute() ||
        !options.target.is_absolute() || !options.old.is_absolute()) {
        Usage();
        return GViewUpdater::EXIT_USAGE;
    }
    return GViewUpdater::Apply(options);
}
} // namespace

#ifdef _WIN32
int wmain(int argc, const wchar_t** argv)
#else
int main(int argc, const char** argv)
#endif
{
    try {
        return Run(argc, argv);
    } catch (...) {
        std::printf("GViewUpdater: unexpected error\n");
        return GViewUpdater::EXIT_ROLLBACK_INCOMPLETE;
    }
}
