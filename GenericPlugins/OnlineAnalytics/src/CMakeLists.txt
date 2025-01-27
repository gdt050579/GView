target_sources(OnlineAnalytics PRIVATE 
    Plugin.cpp
    utils/Hashing.cpp
    utils/Visit.cpp
    providers/VirusTotal.cpp
    providers/Opswat.cpp
    ui/OnlineAnalyticsProvidersUI.cpp
    ui/OnlineAnalyticsResultsUI.cpp)
