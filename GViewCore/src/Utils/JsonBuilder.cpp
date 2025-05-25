#include <cassert>

#include <nlohmann/json.hpp>
#include "Internal.hpp"


using namespace GView::Utils;
using nlohmann::json;

static void ValidateKey(std::string_view key)
{
    if (key.empty()) {
        throw std::invalid_argument("Key cannot be empty");
    }
}

JsonBuilderInterface* JsonBuilderInterface::Create()
{
    return new JsonBuilderImpl();
}
void JsonBuilderInterface::Destroy(JsonBuilderInterface* instance)
{
    delete instance;
}

JsonBuilderImpl::JsonBuilderImpl()
{
    this->data = new json();
}

JsonBuilderImpl::~JsonBuilderImpl()
{
    if (data) {
        delete static_cast<json*>(data);
        data = nullptr;
    }
}

void JsonBuilderImpl::AddString(std::string_view key, std::string_view value, JsonNode parent)
{
    ValidateKey(key);
    json* node = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = std::string(value);
}

void JsonBuilderImpl::AddU16String(std::string_view key, std::u16string_view value, JsonNode parent)
{
    ValidateKey(key);
    json* node = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = std::u16string(value);
}

void JsonBuilderImpl::AddInt(std::string_view key, int64_t value, JsonNode parent)
{
    ValidateKey(key);
    json* node = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = value;
}

void JsonBuilderImpl::AddUInt(std::string_view key, uint64_t value, JsonNode parent)
{
    ValidateKey(key);
    json* node = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = value;
}

void JsonBuilderImpl::AddBool(std::string_view key, bool value, JsonNode parent)
{
    ValidateKey(key);
    json* node                = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = value;
}

JsonBuilderImpl::JsonNode JsonBuilderImpl::StartObject(std::string_view key, JsonNode parent)
{
    ValidateKey(key);
    json* node = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = json::object();
    return &(*node)[std::string(key)];
}

JsonBuilderInterface::JsonNode JsonBuilderImpl::StartArray(std::string_view key, JsonNode parent)
{
    ValidateKey(key);
    json* node = parent ? static_cast<json*>(parent) : static_cast<json*>(data);
    (*node)[std::string(key)] = json::array();
    return JsonNode();
}

void JsonBuilderImpl::AddStringToArray(std::string_view value, JsonNode arrayNode)
{
    assert(arrayNode);
    if (!arrayNode)
        return;
    json* arrayNodeJson = static_cast<json*>(arrayNode);
    arrayNodeJson->push_back(std::string(value));
}


void JsonBuilderImpl::AddU16StringToArray(std::u16string_view value, JsonNode arrayNode)
{
    assert(arrayNode);
    if (!arrayNode)
        return;
    json* arrayNodeJson = static_cast<json*>(arrayNode);
    arrayNodeJson->push_back(std::u16string(value));
}

void JsonBuilderImpl::AddBoolToArray(bool value, JsonNode arrayNode)
{
    assert(arrayNode);
    if (!arrayNode)
        return;
    json* arrayNodeJson = static_cast<json*>(arrayNode);
    arrayNodeJson->push_back(value);
}

void JsonBuilderImpl::AddIntToArray(int64_t value, JsonNode arrayNode)
{
    assert(arrayNode);
    if (!arrayNode)
        return;
    json* arrayNodeJson = static_cast<json*>(arrayNode);
    arrayNodeJson->push_back(value);
}

void JsonBuilderImpl::AddUIntToArray(uint64_t value, JsonNode arrayNode)
{
    assert(arrayNode);
    if (!arrayNode)
        return;
    json* arrayNodeJson = static_cast<json*>(arrayNode);
    arrayNodeJson->push_back(value);
}

std::string JsonBuilderImpl::ToString() const
{
    assert(data);
    return static_cast<json*>(data)->dump(2);
}
