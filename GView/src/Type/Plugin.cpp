#include "GViewApp.hpp"

using namespace GView::Type;


Plugin::Plugin()
{
    // not implemented
}
bool Plugin::Init(const AppCUI::Utils::IniObject& ini, AppCUI::Utils::IniSection section)
{
	auto name = section.GetName();
	CHECK(name.length() > 5, false, "Expected a name after 'type.' !");
	// set the name

	auto Priority = section.GetValue("Priority").ToUInt32(0xFFFF);
	

	const char* name = ini.GetSectionName(is);
	CHECK(name != NULL, false, "");
	unsigned int tr;
	for (tr = 0; (tr < GVIEW_MAX_FILETYPE_NAME - 1) && ((*name) != 0); tr++, name++)
		Name[tr] = (*name);
	Name[tr] = 0;
	// prioritatea
	Priority = MAXVALUE(ini.GetInt32Value(is, "Priority", 1), 1);
	// tipul de obiect
	const char* objTypeName = ini.GetStringValue(is, "ObjectType");
	if (objTypeName == NULL)
		ObjectType = GVIEW_OBJECT_TYPE_FILE;
	else {
		TObjectTypeMap* o = _objectTypeMap_;
		TObjectTypeMap* e = o + sizeof(_objectTypeMap_);
		ObjectType = GVIEW_OBJECT_TYPE_NONE;
		while (o < e)
		{
			if (GLib::Utils::String::Equals(objTypeName, o->Name, true))
			{
				ObjectType = o->Value;
				break;
			}
			o++;
		}
		CHECK(ObjectType != GVIEW_OBJECT_TYPE_NONE, false, "Unknwon object type: '%s' found in config.ini", objTypeName);
	}
	// pattern-urile de match
	MatchPosition = ini.GetInt32Value(is, "PatternPosition", 0);
	const unsigned char* pattern = (const unsigned char*)ini.GetStringValue(is, "Pattern");
	PatternsCount = ExtensionsCount = 0;
	if (pattern != NULL)
	{
		unsigned int index;
		index = 0;
		PatternListSize[index] = 0;
		if (GLib::Utils::String::StartsWith((const char*)pattern, "hex:"))
		{
			// hex mode
			pattern += 4;
			while ((*pattern) != 0)
			{
				if (((*pattern) == ' ') || ((*pattern) == ','))
				{
					pattern++;
					continue;
				}
				if ((*pattern) == '|')
				{
					index++;
					CHECK(index < GVIEW_MAX_PATTERNS, false, "");
					PatternListSize[index] = 0;
					pattern++;
					continue;
				}
				if (((*pattern) == '?') && (pattern[1] == '?'))
				{
					PatternList[index][PatternListSize[index]] = 0xFFFF;
					PatternListSize[index]++;
					if (PatternListSize[index] >= GVIEW_MAX_PATTERN_VALUES)
						break;
					pattern += 2;
				}
				CHECK(GLib::Utils::String::ConvertToUInt16((const char*)pattern, PatternList[index][PatternListSize[index]], 16, 2), false, "");
				PatternListSize[index]++;
				if (PatternListSize[index] >= GVIEW_MAX_PATTERN_VALUES)
					break;
				pattern += 2;
			}
		}
		else
		{
			// string mode
			PatternListSize[0] = 0;
			for (; ((*pattern) != 0) && (PatternListSize[0] < GVIEW_MAX_PATTERN_VALUES); pattern++, PatternListSize[0]++)
			{
				if ((*pattern) == '?')
					PatternList[0][PatternListSize[0]] = 0xFFFF;
				else
					PatternList[0][PatternListSize[0]] = *pattern;
			}
		}
		PatternsCount = index + 1;
	}
	// verific si extensia
	const char* ext = (const char*)ini.GetStringValue(is, "Extensions");
	if (ext != NULL)
	{
		unsigned int poz = 1;
		unsigned int type;
		Extensions[ExtensionsCount][0] = '.';
		for (; (*ext) != 0; ext++)
		{
			type = GLib::Utils::Syntax::Tokenizer::GetCharacterType(*ext);
			if ((type & GLib::Utils::Syntax::CharacterType::AlphaNumeric) != 0)
			{
				Extensions[ExtensionsCount][poz] = *ext;
				poz++;
				CHECK(poz < GVIEW_MAX_EXTENSION_SIZE - 1, false, "Extension too large (max allowed is %d characters) in '%s'", GVIEW_MAX_EXTENSION_SIZE, (const char*)ini.GetStringValue(is, "Extensions"));
				continue;
			}
			if (((*ext) == ',') || ((*ext) == ';'))
			{
				if (poz > 1)
				{
					Extensions[ExtensionsCount][poz] = 0;
					ExtensionsCount++;
					CHECK(ExtensionsCount < GVIEW_MAX_EXTENSIONS, false, "Too many extenstions (max allowed are %d) in '%s'", GVIEW_MAX_EXTENSIONS, (const char*)ini.GetStringValue(is, "Extensions"));
					Extensions[ExtensionsCount][0] = '.';
					poz = 1;
					continue;
				}
			}
		}
		// daca mai am ceva adaugat
		if (poz > 1)
		{
			Extensions[ExtensionsCount][poz] = 0;
			ExtensionsCount++;
		}
	}
	return true;

}