target_sources(JS PRIVATE Simplify.cpp
		FoldConstants.cpp
                ConstPropagation.cpp
		RemoveDeadCode.cpp
		RemoveDummyCode.cpp
		ContextAwareRename.cpp
		Emulate.cpp
		InlineFunctions.cpp
		HoistFunctions.cpp
		RemoveComments.cpp
		MarkAlwaysTrue.cpp
		MarkAlwaysFalse.cpp
		UnrollLoop.cpp
		DumpAST.cpp
		AddStrings.cpp
		ReverseStrings.cpp
		ReplaceConstants.cpp)
