target_sources(GViewCore PRIVATE 
    ErrorDialog.cpp 
    GViewApp.cpp 
    FileWindow.cpp 
    FileWindowProperties.cpp 
    Instance.cpp 
    SelectTypeDialog.cpp 
    TutorialWindow.cpp
    AboutWindow.cpp
    KeyConfiguratorWindow.cpp
    KeyBindings.cpp
    ViewerKeys.cpp
    QueryInterface.cpp
    OptionsWindow.cpp
    LearningModeWindow.cpp
    LearningSubmitDialog.cpp
    UpdateDialog.cpp
    GViewDesktop.cpp
    TemporaryFolder.cpp
    HeadlessAnalysis.cpp
)

# change detection of the persistent storage of the web build: pure logic, built everywhere for the unit tests
target_sources(GViewCore PRIVATE BrowserStorageDiff.cpp)

if (EMSCRIPTEN)
    target_sources(GViewCore PRIVATE BrowserHost.cpp BrowserStorage.cpp StoredFilesWindow.cpp)
endif()

add_testing_sources(GViewCore tests_keybindings.cpp)
add_testing_sources(GViewCore tests_browserstorage.cpp)
add_testing_sources(GViewCore tests_temporaryfolder.cpp)
