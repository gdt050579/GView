target_sources(
	GViewCore PRIVATE 
	DissasmViewer.hpp
	Config.hpp
	Config.cpp
	GoToDialog.cpp
	Instance.cpp
	Settings.cpp
	SelectionEditor.cpp
	UserDefinedTypes.cpp
	DissasmProperties.cpp
	DissasmKeyEvents.cpp
	SingleSelectionDataWindow.cpp
        AdvancedSelection.hpp
	AdvancedSelection.cpp
	DissasmDataTypes.hpp
	DissasmDataTypes.cpp

	x86_x64/DissasmX86.hpp        
	x86_x64/DissasmX86.cpp
)

add_testing_sources(GViewCore tests_dissasmviewer.cpp)