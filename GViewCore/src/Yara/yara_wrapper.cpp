#include "../include/GView.hpp"

#include <yara.h>

void yara_compiler_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data)
{
    const char* level_str = (error_level == YARA_ERROR_LEVEL_ERROR) ? "ERROR" : "WARNING";

    if (file_name != nullptr) {
        LOG_ERROR("[YARA %s] %s:%d: %s", level_str, file_name, line_number, message);
    } else {
        LOG_ERROR("[YARA %s] line %d: %s", level_str, line_number, message);
    }

    if (rule != nullptr && rule->identifier != nullptr) {
        LOG_ERROR(" (in rule: %s)", rule->identifier);
    }
}

namespace GView::Yara
{

using YaraCompilerCallbackInternal =
      int (*)(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data);
using YaraScanCallbackInternal = int (*)(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

// =============== YaraRules ===============
YaraRules::YaraRules(YaraRules&& other) noexcept : rules(other.rules)
{
    other.rules = nullptr;
}

YaraRules::~YaraRules()
{
    if (rules != nullptr) {
        yr_rules_destroy(static_cast<YR_RULES*>(rules));
        rules = nullptr;
    }
}

YaraRules& YaraRules::operator=(YaraRules&& other) noexcept
{
    if (this != &other) {
        if (rules != nullptr) {
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
        }
        rules       = other.rules;
        other.rules = nullptr;
    }
    return *this;
}

void* YaraRules::GetRules() const
{
    return rules;
}

bool YaraRules::SaveRulesToFile(const std::filesystem::path& filePath)
{
    CHECK(rules != nullptr, false, "No rules to save");
    std::string path = filePath.string();
    CHECK(yr_rules_save(static_cast<YR_RULES*>(rules), path.c_str()) == ERROR_SUCCESS, false, "Failed to save rules to file: %s", path.c_str());
    return true;
}

// =============== YaraCompiler ==============
YaraCompiler::YaraCompiler()
{
    compiler                      = nullptr;
    YR_COMPILER** ptr_yr_compiler = reinterpret_cast<YR_COMPILER**>(&compiler);
    int result                    = yr_compiler_create(ptr_yr_compiler);
    CHECKRET(result == ERROR_SUCCESS, "Failed to create YARA compiler: %d", result);

    yr_compiler_set_callback(*ptr_yr_compiler, yara_compiler_callback, nullptr);
}

YaraCompiler::~YaraCompiler()
{
    if (compiler != nullptr) {
        yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler));
        compiler = nullptr;
    }
}

YaraCompiler::YaraCompiler(YaraCompiler&& other) noexcept : compiler(other.compiler), status(other.status)
{
    other.compiler = nullptr;
    other.status   = CompilerStatus::Broken;
}

YaraCompiler& YaraCompiler::operator=(YaraCompiler&& other) noexcept
{
    if (this != &other) {
        if (compiler != nullptr) {
            yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler));
        }
        compiler       = other.compiler;
        status         = other.status;
        other.compiler = nullptr;
        other.status   = CompilerStatus::Broken;
    }
    return *this;
}

bool YaraCompiler::AddRules(const std::filesystem::path& filePath)
{
    CHECK(compiler, false, "Compiler not created");
    CHECK(status == CompilerStatus::Initial, false, "Cannot only add rules in the initial state.");

    std::string path = filePath.string();
    FILE* file       = fopen(path.c_str(), "r");
    CHECK(file, false, "Failed to open file: %s", path.c_str());

    int result = yr_compiler_add_file(static_cast<YR_COMPILER*>(compiler), file, nullptr, path.c_str());
    fclose(file);

    CHECK(result == ERROR_SUCCESS, false, "Failed to add rules to compiler: %d", result);
    return true;
}

std::shared_ptr<YaraRules> YaraCompiler::GetRules()
{
    CHECK(compiler, nullptr, "Compiler not created");

    YR_COMPILER* yr_compiler = static_cast<YR_COMPILER*>(compiler);
    YR_RULES* yr_rules       = nullptr;

    // Each time yr_compiler_get_rules is called it returns a pointer to the same YR_RULES structure.
    // So, its no need to store to YR_RULES.
    int result = yr_compiler_get_rules(yr_compiler, &yr_rules);
    CHECK(result == ERROR_SUCCESS, nullptr, "Failed to compile rules: %d", result);
    status = CompilerStatus::Compiled;
    return std::shared_ptr<YaraRules>(new YaraRules(yr_rules));
}

// =============== YaraScanner ===============

YaraScanner::YaraScanner(std::shared_ptr<YaraRules> rules_ptr, YaraScanCallback scan_callback, void* user_data)
{
    CHECKRET(rules_ptr != nullptr, "YaraRules cannot be null");

    YR_SCANNER** ptr_yr_scanner = reinterpret_cast<YR_SCANNER**>(&scanner);
    YR_RULES* yr_rules          = static_cast<YR_RULES*>(rules_ptr->GetRules());
    int result                  = yr_scanner_create(yr_rules, ptr_yr_scanner);
    CHECKRET(result == ERROR_SUCCESS, "Failed to create YARA scanner: %d", result);

    yr_scanner_set_callback(*ptr_yr_scanner, reinterpret_cast<YaraScanCallbackInternal>(scan_callback), user_data);
    yr_scanner_set_timeout(*ptr_yr_scanner, 0);

    int flags = SCAN_FLAGS_FAST_MODE // flag makes the scanning a little faster by avoiding multiple matches of the same string when not necessary
                | SCAN_FLAGS_REPORT_RULES_MATCHING; // control whether the callback is invoked for rules that are matching

    yr_scanner_set_flags(*ptr_yr_scanner, flags);
}

YaraScanner::~YaraScanner()
{
    if (scanner != nullptr) {
        yr_scanner_destroy(static_cast<YR_SCANNER*>(scanner));
        scanner = nullptr;
    }
}

YaraScanner::YaraScanner(YaraScanner&& other) noexcept : scanner(other.scanner)
{
    other.scanner = nullptr;
}

YaraScanner& YaraScanner::operator=(YaraScanner&& other) noexcept
{
    if (this != &other) {
        if (scanner != nullptr) {
            yr_scanner_destroy(static_cast<YR_SCANNER*>(scanner));
        }

        scanner       = other.scanner;
        other.scanner = nullptr;
    }
    return *this;
}

bool YaraScanner::ScanFile(const std::filesystem::path& filePath)
{
    CHECK(scanner != nullptr, false, "Scanner not created");

    std::string path       = filePath.string();
    YR_SCANNER* yr_scanner = static_cast<YR_SCANNER*>(scanner);
    int result             = yr_scanner_scan_file(yr_scanner, path.c_str());
    CHECK(result == ERROR_SUCCESS, false, "Failed to scan file: %s, error: %d", path.c_str(), result);
    return true;
}

bool YaraScanner::ScanBuffer(const BufferView& buffer)
{
    CHECK(scanner != nullptr, false, "Scanner not created");

    YR_SCANNER* yr_scanner = static_cast<YR_SCANNER*>(scanner);
    int result             = yr_scanner_scan_mem(yr_scanner, buffer.GetData(), buffer.GetLength());
    CHECK(result == ERROR_SUCCESS, false, "Failed to scan buffer, error: %d", result);
    return true;
}

// =============== YaraManager ===============
YaraManager::~YaraManager()
{
    Finalize();
}

YaraManager& YaraManager::GetInstance()
{
    static YaraManager instance;
    return instance;
}

bool YaraManager::Initialize()
{
    if (!initialized) {
        int result = yr_initialize();
        CHECK(result == ERROR_SUCCESS, false, "Failed to initialize YARA: %d", result);
        initialized = true;
        return true;
    }
    return true;
}

void YaraManager::Finalize()
{
    if (initialized) {
        yr_finalize();
        initialized = false;
    }
}

std::unique_ptr<YaraCompiler> YaraManager::GetNewCompiler() const
{
    CHECK(initialized, nullptr, "YARA not initialized");
    return std::unique_ptr<YaraCompiler>(new YaraCompiler());
}

std::shared_ptr<YaraRules> YaraManager::LoadRules(const std::filesystem::path& filePath)
{
    CHECK(initialized, nullptr, "YARA not initialized");

    std::string path   = filePath.string();
    YR_RULES* yr_rules = nullptr;
    int result         = yr_rules_load(path.c_str(), &yr_rules);
    CHECK(result == ERROR_SUCCESS, nullptr, "Failed to load rules from file: %s", path.c_str());
    return std::shared_ptr<YaraRules>(new YaraRules(yr_rules));
}

} // namespace GView::Yara