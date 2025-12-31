#include "../include/GView.hpp"

#include <string>
#include <yara.h>

using YaraScanCallback = int (*)(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

int callback_function(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) 
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
        if (!CreateCompiler()) {
            return false;
        }
        LoadRules("rules.yara");
        return true;
    }

    YaraScanner::~YaraScanner() {
        if (rules) {
            SaveRules("rules.yara");
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
            rules = nullptr;
        }

        if (compiler) {
            yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler));
            compiler = nullptr;
        }
        
        yr_finalize();
    }

    bool YaraScanner::CreateCompiler() {
        YR_COMPILER* comp;
        int result = yr_compiler_create(&comp);
        if (result == ERROR_SUCCESS) {
            compiler = comp;
            return true;
        }
        return false;
    }

    bool YaraScanner::AddRules(const std::string& filePath) {
        if (!compiler) {
            return false;
        }
        
        FILE* file = fopen(filePath.c_str(), "r");
        if (!file) {
            return false;
        }
        
        int result = yr_compiler_add_file(static_cast<YR_COMPILER*>(compiler), file, nullptr, filePath.c_str());
        fclose(file);
        
        return result == ERROR_SUCCESS;
    }

    bool YaraScanner::CompileRules() {
        if (!compiler) {
            return false;
        }
        
        if (rules) {
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
            rules = nullptr;
        }
        
        YR_RULES* compiled_rules;
        int result = yr_compiler_get_rules(static_cast<YR_COMPILER*>(compiler), &compiled_rules);
        if (result == ERROR_SUCCESS) {
            rules = compiled_rules;
            return true;
        }
        return false;
    }

    bool YaraScanner::LoadRules(const std::string& filePath) {
        if (rules) {
            yr_rules_destroy(static_cast<YR_RULES*>(rules));
            rules = nullptr;
        }
        
        YR_RULES* loaded_rules;
        int result = yr_rules_load(filePath.c_str(), &loaded_rules);
        if (result == ERROR_SUCCESS) {
            rules = loaded_rules;
            return true;
        }
        return false;
    }

    bool YaraScanner::SaveRules(const std::string& filePath) {
        if (!rules) {
            return false;
        }
        
        int result = yr_rules_save(static_cast<YR_RULES*>(rules), filePath.c_str());
        return result == ERROR_SUCCESS;
    }

    bool YaraScanner::ScanFile(const std::string& filePath) {
        if (!rules) {
            return false;
        }
        
        int flags = SCAN_FLAGS_FAST_MODE // flag makes the scanning a little faster by avoiding multiple matches of the same string when not necessary
            | SCAN_FLAGS_REPORT_RULES_MATCHING; // control whether the callback is invoked for rules that are matching

        FILE* yara_matches_file = fopen("yara_matches.txt", "w");
        if (!yara_matches_file) {
            return false;
        }
        
        int result = yr_rules_scan_file(static_cast<YR_RULES*>(rules), filePath.c_str(), flags, callback_function, yara_matches_file, 0);
        fclose(yara_matches_file);
        return result == ERROR_SUCCESS;
    }

} // namespace GView::Yara