target_sources(JS PRIVATE FoldConstants.cpp
                ConstPropagation.cpp
		RemoveDeadCode.cpp
		ContextAwareRename.cpp
		Emulate.cpp
		RemoveComments.cpp
		MarkAlwaysTrue.cpp
		UnrollLoop.cpp
		AddStrings.cpp
		ReverseStrings.cpp
		ReplaceConstants.cpp)
