target_sources(JS PRIVATE FoldConstants.cpp
                ConstPropagation.cpp
		RemoveDeadCode.cpp
		ContextAwareRename.cpp
		Emulate.cpp
		InlineFunctions.cpp
		HoistFunctions.cpp
		RemoveComments.cpp
		MarkAlwaysTrue.cpp
		UnrollLoop.cpp
		DumpAST.cpp
		AddStrings.cpp
		ReverseStrings.cpp
		ReplaceConstants.cpp)
