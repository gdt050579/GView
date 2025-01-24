#include "log.hpp"

namespace GView::Type::LOG
{
using namespace GView::View::LexicalViewer;

namespace CharacterType
{
    constexpr uint32 ip_address    = 0;
    constexpr uint32 dash          = 1;
    constexpr uint32 bracket_open  = 2;
    constexpr uint32 bracket_close = 3;
    constexpr uint32 quotes        = 4;
    constexpr uint32 space         = 5;
    constexpr uint32 alphanum      = 6;
    constexpr uint32 invalid       = 7;
    constexpr uint32 colon         = 8;
    constexpr uint32 slash         = 9;
    constexpr uint32 period        = 10;

    uint32 GetCharacterType(char16 ch)
    {
        if (ch == '.')
            return period;
        if (ch == '-')
            return dash;
        if (ch == '[')
            return bracket_open;
        if (ch == ']')
            return bracket_close;
        if (ch == '"')
            return quotes;
        if (ch == ':')
            return colon;
        if (ch == '/')
            return slash; 
        if (ch == ' ' || ch == '\t')
            return space;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')
            return alphanum;
        return invalid;
    }
} // namespace CharacterType

LogFile::LogFile()
{
    entryCount     = 0;
    errorCount     = 0;
    warningCount   = 0;
    infoCount      = 0;
    firstTimestamp = "";
    lastTimestamp  = "";
    ipAddresses.clear();
}

#define CHAR_CASE(char_type, align)                                                                                                                            \
    case CharacterType::char_type:                                                                                                                             \
        syntax.tokens.Add(TokenType::char_type, pos, pos + 1, TokenColor::Operator, TokenDataType::None, (align), TokenFlags::DisableSimilaritySearch);        \
        pos++;                                                                                                                                                 \
        break;


bool IsIPAddress(const std::string_view& str)
{
    size_t dotCount   = 0;
    size_t digitCount = 0;
    int segmentValue  = 0;

    for (char c : str) {
        if (c == '.') {
            dotCount++;
            if (digitCount == 0 || segmentValue > 255)
                return false;
            digitCount   = 0;
            segmentValue = 0;
        } else if (c >= '0' && c <= '9') {
            digitCount++;
            segmentValue = segmentValue * 10 + (c - '0');
            if (digitCount > 3 || segmentValue > 255)
                return false;
        } else {
            return false;
        }
    }

    return dotCount == 3 && digitCount > 0 && segmentValue <= 255;
}

void LogFile::ParseFile(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    auto len  = syntax.text.Len();
    auto pos  = 0u;
    auto next = 0u;

    while (pos < len) {
        auto char_type = CharacterType::GetCharacterType(syntax.text[pos]);
        switch (char_type) {
            CHAR_CASE(ip_address, TokenAlignament::None);
            CHAR_CASE(dash, TokenAlignament::None);
            CHAR_CASE(bracket_open, TokenAlignament::None);
            CHAR_CASE(bracket_close, TokenAlignament::None);
            CHAR_CASE(quotes, TokenAlignament::None);
            CHAR_CASE(space, TokenAlignament::None);
            CHAR_CASE(colon, TokenAlignament::None);
            CHAR_CASE(slash, TokenAlignament::None);
            CHAR_CASE(period, TokenAlignament::None);
        case CharacterType::alphanum: {
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            auto substring = syntax.text.GetSubString(pos, next);
            std::string word(substring.begin(), substring.end());

            if (IsIPAddress(word)) {
                ipAddresses.push_back(std::string(word));
                syntax.tokens.Add(TokenType::ip_address, pos, next, TokenColor::Keyword, TokenAlignament::None);
            } else {
                syntax.tokens.Add(TokenType::value, pos, next, TokenColor::Word, TokenAlignament::AddSpaceBefore);
            }

            pos = next;
            break;
        }
        case CharacterType::invalid:
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            syntax.tokens.Add(TokenType::invalid, pos, next, TokenColor::Error, TokenAlignament::AddSpaceBefore).SetError("Invalid character in log file");
            pos = next;
            break;
        }
    }
}

void LogFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    // Logs usually don't have complex blocks like JSON, so we'll just handle each entry as a single block.
    auto len = syntax.tokens.Len();
    auto pos = 0u;

    for (; pos < len; pos++) {
        if (syntax.tokens[pos].GetTypeID(TokenType::invalid) == TokenType::value) {
            auto start = pos;
            while (pos < len && syntax.tokens[pos].GetTypeID(TokenType::invalid) != TokenType::invalid)
                pos++;
            syntax.blocks.Add(start, pos - 1, BlockAlignament::ParentBlockWithIndent, BlockFlags::EndMarker);
        }
    }

    // Add fold messages
    auto blocks_len = syntax.blocks.Len();
    LocalString<128> tmp;
    for (auto index = 0u; index < blocks_len; index++) {
        auto block = syntax.blocks[index];
        block.SetFoldMessage(tmp.Format("Tokens: %d", block.GetEndToken().GetIndex() - block.GetStartToken().GetIndex()));
    }
}

void LogFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for a log file format
}

void LogFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id) {
    default:
        str.SetFormat("Unknown: 0x%08X", id);
        break;
    }
}

void LogFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    ParseFile(syntax);
    BuildBlocks(syntax);

    AnalyzeLogFile();
}

bool LogFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
{
    return TextParser::ExtractContentFromString(string, result, StringFormat::All);
}

bool LogFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
{
    NOT_IMPLEMENTED(false);
}

std::string ExtractMessage(const std::string_view& line)
{
    // assume messages start after a timestamp and severity
    size_t messageStart = line.find("] ");
    if (messageStart != std::string_view::npos)
        return std::string(line.substr(messageStart + 2));
    return std::string(line);
}

std::string CategorizeMessage(const std::string& message)
{
    if (message.find("timeout") != std::string::npos)
        return "Timeouts";
    if (message.find("error") != std::string::npos || message.find("failure") != std::string::npos)
        return "Errors";
    if (message.find("login") != std::string::npos || message.find("logout") != std::string::npos || message.find("sign") != std::string::npos ||
        message.find("user") != std::string::npos)
        return "User Actions";
    return "General";
}

void LogFile::AnalyzeLogFile()
{
    auto& data = this->obj->GetData();
    auto size  = data.GetSize();
    std::unordered_set<std::string> uniqueIPAddresses;

    entryCount   = 0;
    errorCount   = 0;
    warningCount = 0;
    infoCount    = 0;
    firstTimestamp.clear();
    lastTimestamp.clear();
    logCategories.clear();

    auto bufferView = data.GetEntireFile();
    if (!bufferView.IsValid()) {
        return;
    }
    std::string_view logContent(reinterpret_cast<const char*>(bufferView.GetData()), bufferView.GetLength());

    size_t pos = 0;

    while (pos < logContent.size()) {
        // Extract a single log entry (assuming each log entry ends with a newline)
        size_t endPos = logContent.find('\n', pos);
        if (endPos == std::string_view::npos)
            endPos = logContent.size();

        std::string_view line = logContent.substr(pos, endPos - pos);

        if (!line.empty()) {
            entryCount++;

            if (line.find("ERROR") != std::string_view::npos)
                errorCount++;
            else if (line.find("WARN") != std::string_view::npos)
                warningCount++;
            else if (line.find("INFO") != std::string_view::npos)
                infoCount++;

            std::string message = ExtractMessage(line);
            std::string category = CategorizeMessage(message);
            auto& summary = logCategories[category];
            summary.count++;
            if (summary.recentMessages.size() < 5) { // memorizing only the latest 5 messages for the category
                summary.recentMessages.push_back(message);
            }

            std::regex timestampRegex(R"(\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\])");
            auto match = std::smatch();
            std::string lineStr(line);
            if (std::regex_search(lineStr, match, timestampRegex)) {
                std::string timestamp = match.str();
                if (firstTimestamp.empty())
                    firstTimestamp = timestamp;
                lastTimestamp = timestamp;
            }

            std::regex ipRegex(R"((\d{1,3}\.){3}\d{1,3})");
            if (std::regex_search(lineStr, match, ipRegex)) {
                std::string ipAddress = match.str();
                uniqueIPAddresses.insert(ipAddress);
            }
        }
        pos = endPos + 1;
    }
    ipAddresses.clear();
    ipAddresses.insert(ipAddresses.end(), uniqueIPAddresses.begin(), uniqueIPAddresses.end());
}

LogFile::~LogFile()
{
}
} // namespace GView::Type::LOG
