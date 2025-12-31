#include "../include/GView.hpp"

#include <yara.h>

using YaraScanCallback = int (*)(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

int yara_scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) 
{
    switch (message) {
        case CALLBACK_MSG_RULE_MATCHING: {
            YR_RULE* rule = static_cast<YR_RULE*>(message_data);
            FILE* file = static_cast<FILE*>(user_data);
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
    bool YaraScanner::Init() {
        yr_initialize();
        CHECK(CreateCompiler(), false, "Failed to create YARA compiler");
        LoadRules("rules.yara");
        return true;
    }

    YaraScanner::~YaraScanner() {
        if (rules != nullptr) {
            SaveRules("rules.yara");
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
            rules = nullptr;
        }

        if (compiler != nullptr) {
            yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler));
            compiler = nullptr;
        }
        
        yr_finalize();
    }

    bool YaraScanner::CreateCompiler() {
        YR_COMPILER** ptr_yr_compiler = reinterpret_cast<YR_COMPILER**>(&compiler);
        CHECK(yr_compiler_create(ptr_yr_compiler) == ERROR_SUCCESS, false, "Failed to create YARA compiler");
        return true;
    }

    bool YaraScanner::AddRules(const std::string& filePath) {
        CHECK(compiler, false, "Compiler not created");
        CHECK(!compiled, false, "Cannot add rules after CompileRules() has been called.");
        
        FILE* file = fopen(filePath.c_str(), "r");
        CHECK(file, false, "Failed to open file: %s", filePath.c_str());
        
        int result = yr_compiler_add_file(static_cast<YR_COMPILER*>(compiler), file, nullptr, filePath.c_str());
        fclose(file);
        
        return result == ERROR_SUCCESS;
    }

    bool YaraScanner::CompileRules() {
        CHECK(compiler, false, "Compiler not created");
        CHECK(!compiled, false, "Rules already compiled");
        
        if (rules != nullptr) {
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
            rules = nullptr;
        }
        
        YR_COMPILER* yr_compiler = static_cast<YR_COMPILER*>(compiler);
        YR_RULES** ptr_yr_rules = reinterpret_cast<YR_RULES**>(&rules);
        CHECK(yr_compiler_get_rules(yr_compiler, ptr_yr_rules) == ERROR_SUCCESS, false, "Failed to compile rules");
        
        compiled = true;

        return true;
    }

    bool YaraScanner::LoadRules(const std::string& filePath) {
        if (rules != nullptr) {
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
            rules = nullptr;
        }
        
        YR_RULES** ptr_yr_rules = reinterpret_cast<YR_RULES**>(&rules);
        CHECK(yr_rules_load(filePath.c_str(), ptr_yr_rules) == ERROR_SUCCESS, false, "Failed to load rules from file: %s", filePath.c_str());
        return true;
    }

    bool YaraScanner::SaveRules(const std::string& filePath) {
        CHECK(rules != nullptr, false, "Rules not loaded");
        
        CHECK(yr_rules_save(static_cast<YR_RULES*>(rules), filePath.c_str()) == ERROR_SUCCESS, false, "Failed to save rules to file: %s", filePath.c_str());
        return true;
    }

    bool YaraScanner::ScanFile(const std::string& filePath) {
        CHECK(rules != nullptr, false, "Rules not loaded");
        
        int flags = SCAN_FLAGS_FAST_MODE // flag makes the scanning a little faster by avoiding multiple matches of the same string when not necessary
            | SCAN_FLAGS_REPORT_RULES_MATCHING; // control whether the callback is invoked for rules that are matching

        FILE* yara_matches_file = fopen("yara_matches.txt", "w");
        CHECK(yara_matches_file != nullptr, false, "Failed to open file: yara_matches.txt");

        int result = yr_rules_scan_file(static_cast<YR_RULES*>(rules), filePath.c_str(), flags, yara_scan_callback, yara_matches_file, 0);
        fclose(yara_matches_file);
        CHECK(result == ERROR_SUCCESS, false, "Failed to scan file: %s", filePath.c_str());
        
        return true;
    }

} // namespace GView::Yara