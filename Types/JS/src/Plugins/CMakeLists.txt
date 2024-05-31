target_sources(JS PRIVATE BuildAST.cpp
		AddStrings.cpp
                ConstPropagation.cpp
		ReplaceConstants.cpp
		ReverseStrings.cpp
		RemoveComments.cpp
		MarkAlwaysTrue.cpp
		UnrollLoop.cpp)
