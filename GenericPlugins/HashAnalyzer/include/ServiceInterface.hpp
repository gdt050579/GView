#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace GView::GenericPlugins::HashAnalyzer
{

/**
 * Defineste tipul de hash pe care îl trimitem la analiza.
 */
enum class HashKind { MD5, SHA1, SHA256 };

/**
 * Structura care retine rezultatul analizei primite de la serviciul online (ex: VirusTotal).
 * Aceasta este structura pe care o va afisa UI-ul (Task 6 & 7).
 */
struct AnalysisResult {
    std::string serviceName; // Ex: "VirusTotal"
    std::string queryHash;   // Hash-ul cautat

    bool found;   // True daca fisierul a fost gasit în baza de date a serviciului
    bool success; // True daca apelul API a reusit 

    uint32_t detectionCount; // Numarul de motoare care au detectat fi?ierul ca mali?ios
    uint32_t totalEngines;   // Numarul total de motoare folosite la scanare

    std::string scanDate;     // Data ultimei scanari
    std::string permalink;    // Link catre raportul web complet
    std::string errorMessage; // Mesaj de eroare (daca success == false)

    // Rezultate detaliate per vendor (Ex: "Microsoft" -> "Trojan:Win32/Emotet")
    // Folosim std::map pentru a fi usor de afisat într-un ListView (similar cu Hashes.cpp)
    std::map<std::string, std::string> vendorResults;

    AnalysisResult() : found(false), success(false), detectionCount(0), totalEngines(0)
    {
    }
};

class IAnalysisService
{
  public:
    virtual ~IAnalysisService() = default;

    // Returneaza ID-ul intern al serviciului (folosit în setari/config)
    // Ex: "virustotal"
    virtual const char* GetID() const = 0;

    // Returneaza numele afisat utilizatorului
    // Ex: "VirusTotal Public API"
    virtual const char* GetName() const = 0;

    // Verifica daca serviciul are API Key setat în configura?ie
    virtual bool IsConfigured() = 0;

    // Aceasta metoda este blocanta (va fi apelata de pe un thread separat în UI).
    virtual AnalysisResult AnalyzeHash(const std::string& hash, HashKind type) = 0;
};

/**
 * Managerul de servicii (Singleton).
 * Gestioneaza lista de servicii disponibile.
 */
class ServiceManager
{
    std::vector<std::unique_ptr<IAnalysisService>> services;

    ServiceManager() = default; 

  public:
    // Singleton access
    static ServiceManager& Get()
    {
        static ServiceManager instance;
        return instance;
    }

    // Înregistreaza un serviciu nou 
    void RegisterService(std::unique_ptr<IAnalysisService> service)
    {
        if (service) {
            services.push_back(std::move(service));
        }
    }

    // Returneaza lista de servicii (pentru a popula Dropdown-ul din UI)
    const std::vector<std::unique_ptr<IAnalysisService>>& GetServices() const
    {
        return services;
    }

    IAnalysisService* GetServiceByID(const std::string& id)
    {
        for (const auto& svc : services) {
            if (svc->GetID() == id)
                return svc.get();
        }
        return nullptr;
    }
};

} 