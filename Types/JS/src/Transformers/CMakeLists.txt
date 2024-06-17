target_sources(JS PRIVATE DynamicPropagator.cpp
		ConstFolder.cpp
		ConstPropagator.cpp
		ContextAwareRenamer.cpp
		DeadCodeRemover.cpp
		DummyCodeRemover.cpp
		FunctionHoister.cpp
		FunctionInliner.cpp)
