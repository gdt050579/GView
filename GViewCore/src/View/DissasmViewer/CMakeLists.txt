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
	DissasmCodeZone.hpp
	DissasmCodeZone.cpp
	DissasmFunctionUtils.hpp
	DissasmFunctionUtils.cpp
	DissasmCache.hpp
	DissasmCache.cpp

	x86_x64/DissasmX86.hpp        
	x86_x64/DissasmX86.cpp

	jclass/allocator.cpp
	jclass/ast.cpp
	jclass/ast.hpp
	jclass/buffer_reader.cpp
	jclass/class_parser.cpp
	jclass/class_parser.hpp
	jclass/global.hpp
	jclass/raw_opcodes.hpp
	jclass/DissasmJClass.cpp
)

add_testing_sources(GViewCore tests_dissasmviewer.cpp)
target_sources(GViewCore PRIVATE jclass/GViewJClass.natvis)