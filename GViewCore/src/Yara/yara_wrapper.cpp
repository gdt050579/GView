#include "../include/GView.hpp"

#include <yara.h>

void yara_compiler_callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule, const char* message, void* user_data) {
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

int yara_scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    switch (message) {
        case CALLBACK_MSG_RULE_MATCHING: {
            YR_RULE* rule = reinterpret_cast<YR_RULE*>(message_data);
            FILE* file = reinterpret_cast<FILE*>(user_data);
            fprintf(file, "Rule matching: %s\n", rule->identifier);
            return CALLBACK_CONTINUE;
        } break;
        case CALLBACK_MSG_TOO_MANY_MATCHES: {
            return CALLBACK_CONTINUE;
        }
        case CALLBACK_MSG_SCAN_FINISHED: {
            return CALLBACK_CONTINUE;
        } break;
        default:
            break;
    }
    return CALLBACK_CONTINUE;
}


namespace GView::Yara
{
// =============== YaraRules ===============    
    YaraRules::YaraRules(YaraRules&& other) noexcept : rules(other.rules) {
        other.rules = nullptr;
    }

    YaraRules::~YaraRules() {
        if (rules != nullptr) {
            yr_rules_destroy(reinterpret_cast<YR_RULES*>(rules));
            rules = nullptr;
        }
    }
    
    YaraRules& YaraRules::operator=(YaraRules&& other) noexcept {
        if (this != &other) {
            if (rules != nullptr) {
                yr_rules_destroy(reinterpret_cast<YR_RULES*>(rules));
            }
            rules = other.rules;
            other.rules = nullptr;
        }
        return *this;
    }
    
    void* YaraRules::GetRules() const { 
        return rules; 
    }

    bool YaraRules::SaveRulesToFile(const std::string_view& filePath) {
        CHECK(rules != nullptr, false, "No rules to save");
        CHECK(yr_rules_save(reinterpret_cast<YR_RULES*>(rules), filePath.data()) == ERROR_SUCCESS, false, "Failed to save rules to file: %s", filePath.data());
        return true;
    }

// =============== YaraCompiler ==============
    YaraCompiler::YaraCompiler() {
        compiler = nullptr;
        YR_COMPILER** ptr_yr_compiler = reinterpret_cast<YR_COMPILER**>(&compiler);
        int result = yr_compiler_create(ptr_yr_compiler);
        CHECKRET(result == ERROR_SUCCESS, "Failed to create YARA compiler: %d", result);

        yr_compiler_set_callback(*ptr_yr_compiler, yara_compiler_callback, nullptr);
    }
    
    YaraCompiler::~YaraCompiler() {
        if (compiler != nullptr) {
            yr_compiler_destroy(reinterpret_cast<YR_COMPILER*>(compiler));
            compiler = nullptr;
        }
    }
    
    YaraCompiler::YaraCompiler(YaraCompiler&& other) noexcept 
        : compiler(other.compiler), compiled(other.compiled) {
        other.compiler = nullptr;
        other.compiled = false;
    }
    
    YaraCompiler& YaraCompiler::operator=(YaraCompiler&& other) noexcept {
        if (this != &other) {
            if (compiler != nullptr) {
                yr_compiler_destroy(reinterpret_cast<YR_COMPILER*>(compiler));
            }
            compiler = other.compiler;
            compiled = other.compiled;
            other.compiler = nullptr;
            other.compiled = false;
        }
        return *this;
    }

    bool YaraCompiler::AddRules(const std::string_view& filePath) {
        CHECK(compiler, false, "Compiler not created");
        CHECK(!compiled, false, "Cannot add new rules after compiling.");
        
        FILE* file = fopen(filePath.data(), "r");
        CHECK(file, false, "Failed to open file: %s", filePath.data());
        
        int result = yr_compiler_add_file(reinterpret_cast<YR_COMPILER*>(compiler), file, nullptr, filePath.data());
        fclose(file);
        
        CHECK(result == ERROR_SUCCESS, false, "Failed to add rules to compiler: %d", result);
        return true;
    }

    YaraRules* YaraCompiler::GetRules() {
        CHECK(compiler, nullptr, "Compiler not created");
        
        YR_COMPILER* yr_compiler = reinterpret_cast<YR_COMPILER*>(compiler);
        YR_RULES* yr_rules = nullptr;

        // Each time yr_compiler_get_rules is called it returns a pointer to the same YR_RULES structure.
        // So, its no need to store to YR_RULES.
        int result = yr_compiler_get_rules(yr_compiler, &yr_rules);
        CHECK(result == ERROR_SUCCESS, nullptr, "Failed to compile rules: %d", result);
        compiled = true;
        return new YaraRules(yr_rules);
    }

// =============== YaraScanner ===============

    YaraScanner::YaraScanner(YaraRules* rules, const std::string_view& callbackFilePath) {
        YR_SCANNER** ptr_yr_scanner = reinterpret_cast<YR_SCANNER**>(&scanner);
        YR_RULES* yr_rules = reinterpret_cast<YR_RULES*>(rules->GetRules());
        int result = yr_scanner_create(yr_rules, ptr_yr_scanner);
        CHECKRET(result == ERROR_SUCCESS, "Failed to create YARA scanner: %d", result);

        // TODO: replace with a better option
        callbackFile = fopen(callbackFilePath.data(), "w");
        CHECKRET(callbackFile, "Failed to open file: %s", callbackFilePath.data());
        // ==================================
        yr_scanner_set_callback(*ptr_yr_scanner, yara_scan_callback, callbackFile);
        yr_scanner_set_timeout(*ptr_yr_scanner, 0);

        int flags = SCAN_FLAGS_FAST_MODE // flag makes the scanning a little faster by avoiding multiple matches of the same string when not necessary
            | SCAN_FLAGS_REPORT_RULES_MATCHING; // control whether the callback is invoked for rules that are matching

        yr_scanner_set_flags(*ptr_yr_scanner, flags);
    }

    YaraScanner::~YaraScanner() {
        if (scanner != nullptr) {
            yr_scanner_destroy(reinterpret_cast<YR_SCANNER*>(scanner));
            scanner = nullptr;
        }
        if (callbackFile != nullptr) {
            fclose(callbackFile);
            callbackFile = nullptr;
        }
    }
    
    YaraScanner::YaraScanner(YaraScanner&& other) noexcept 
        : scanner(other.scanner), callbackFile(other.callbackFile) {
        other.scanner = nullptr;
        other.callbackFile = nullptr;
    }
    
    YaraScanner& YaraScanner::operator=(YaraScanner&& other) noexcept {
        if (this != &other) {
            if (scanner != nullptr) {
                yr_scanner_destroy(reinterpret_cast<YR_SCANNER*>(scanner));
            }
            if (callbackFile != nullptr) {
                fclose(callbackFile);
            }

            scanner = other.scanner;
            callbackFile = other.callbackFile;

            YR_SCANNER* yr_scanner = reinterpret_cast<YR_SCANNER*>(scanner);
            yr_scanner_set_callback(yr_scanner, yara_scan_callback, callbackFile);

            other.scanner = nullptr;
            other.callbackFile = nullptr;
        }
        return *this;
    }
    
    bool YaraScanner::ScanFile(const std::string_view& filePath) {
        CHECK(scanner != nullptr, false, "Scanner not created");
        CHECK(callbackFile != nullptr, false, "Callback file not created");

        YR_SCANNER* yr_scanner = reinterpret_cast<YR_SCANNER*>(scanner);
        int result = yr_scanner_scan_file(yr_scanner, filePath.data());
        CHECK(result == ERROR_SUCCESS, false, "Failed to scan file: %s, error: %d", filePath.data(), result);
        return true;
    }

// =============== YaraManager ===============
    YaraManager* YaraManager::instance = nullptr;

    YaraManager::~YaraManager() {
        Finalize();
    }

    YaraManager* YaraManager::GetInstance() {
        if (instance == nullptr) {
            instance = new YaraManager();
        }
        return instance;
    }

    void YaraManager::DestroyInstance() {
        if (instance != nullptr) {
            delete instance;
            instance = nullptr;
        }
    }

    bool YaraManager::Initialize() {
        if (!initialized) {
            int result = yr_initialize();
            CHECK(result == ERROR_SUCCESS, false, "Failed to initialize YARA: %d", result);
            initialized = true;
            return true;
        }
        return true;
    }

    void YaraManager::Finalize() {
        if (initialized) {
            yr_finalize();
            initialized = false;
        }
    }

    YaraCompiler* YaraManager::GetNewCompiler() const {
        return new YaraCompiler();
    }

    YaraRules* YaraManager::LoadRules(const std::string_view& filePath) {
        YR_RULES* yr_rules = nullptr;
        int result = yr_rules_load(filePath.data(), &yr_rules); 
        CHECK(result == ERROR_SUCCESS, nullptr, "Failed to load rules from file: %s", filePath.data());
        return new YaraRules(yr_rules);
    }
    
} // namespace GView::Yara