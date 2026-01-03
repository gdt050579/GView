#pragma once

#include "ServiceInterface.hpp"

namespace GView::GenericPlugins::HashAnalyzer
{

// Aceasta este clasa care simulează serviciul (MOCK)
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
        return AnalysisResult(); // Returnează gol
    }
};

// Funcție helper care injectează serviciul de test
inline void RegisterTestService()
{
    auto& manager = ServiceManager::Get();

    // Dacă lista e goală, înseamnă că nu avem VirusTotal real, deci băgăm Dummy-ul
    if (manager.GetServices().empty()) {
        manager.RegisterService(std::make_unique<DummyService>());
    }
}

} // namespace GView::GenericPlugins::HashAnalyzer