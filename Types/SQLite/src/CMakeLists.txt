find_package(unofficial-sqlite3 CONFIG REQUIRED)
target_link_libraries(SQLite PRIVATE unofficial::sqlite3::sqlite3)

target_sources(SQLite PRIVATE 
	PanelInformation.cpp
	CountInformation.cpp
	SQLiteDB.hpp
	SQLiteFile.cpp
	TablesDialog.cpp
	sqlite.cpp) 