#pragma once

#include "ServiceInterface.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{

class DummyService : public IAnalysisService
{
  public:
    const char* GetID() const override
    {
        return "dummy";
    }
    const char* GetName() const override
    {
        return "Demo Service Loaded For Test"; 
    }
    bool IsConfigured() override
    {
        return true;
    }
    AnalysisResult AnalyzeHash(const std::string& hash, HashKind type) override
    {
        return AnalysisResult(); 
    }
};

inline void RegisterTestService()
{
    auto& manager = ServiceManager::Get();

    if (manager.GetServices().empty()) {
        manager.RegisterService(std::make_unique<DummyService>());
    }
}

} 