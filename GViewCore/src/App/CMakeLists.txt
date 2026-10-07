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
)

add_testing_sources(GViewCore tests_keybindings.cpp)
