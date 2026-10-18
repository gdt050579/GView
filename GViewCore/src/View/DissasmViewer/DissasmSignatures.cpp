#include "DissasmSignatures.hpp"
#include "DissasmCodeZone.hpp"
#include "DissasmFunctionUtils.hpp"
#include "x86_x64/X86InstructionInfo.hpp"

#include <algorithm>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

using namespace GView::View::DissasmViewer;
using nlohmann::json;

namespace
{
constexpr size_t KEY_TOKENS    = DISSASM_SIGNATURE_MIN_FIXED_BYTES; // every pattern has at least so many bytes
constexpr size_t MAX_NAME_SIZE = 1024;
constexpr int16 MASKED         = -1;

// the signatures of ARM and Thumb code are interchangeable (a file mixes both)
std::string_view ArchitectureFamily(const DissasmCodeZone& zone)
{
    return zone.IsArm32Code() ? std::string_view("ARM") : std::string_view(zone.GetArchitectureName());
}

bool IsAutomaticName(std::string_view name)
{
    return name.empty() || name == "EntryPoint" || name.starts_with("sub_") || name.starts_with("loc_") || name.starts_with("j_");
}

void MaskRange(std::vector<bool>& masked, size_t offset, size_t size)
{
    for (size_t index = offset; index < offset + size && index < masked.size(); index++)
        masked[index] = true;
}

// x86 / x64: the rel32 of the calls / jumps (out of the function), the RIP relative displacements, the absolute addresses of 32 bit code
void MaskX86(const cs_insn& insn, bool is64, std::vector<bool>& masked)
{
    if (insn.id == 0 || !insn.detail)
        return;
    const cs_x86& x86      = insn.detail->x86;
    const auto& encoding   = x86.encoding;
    const auto flow        = GetX86Flow(insn);
    if (IsX86Branch(flow) && encoding.imm_size >= 4)
        MaskRange(masked, encoding.imm_offset, encoding.imm_size);
    for (uint8 index = 0; index < x86.op_count; index++) {
        const cs_x86_op& op = x86.operands[index];
        if (op.type == X86_OP_MEM && encoding.disp_size > 0) {
            const bool isRipRelative = op.mem.base == X86_REG_RIP;
            const bool isAbsolute    = !is64 && op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID;
            if (isRipRelative || isAbsolute)
                MaskRange(masked, encoding.disp_offset, encoding.disp_size);
        } else if (op.type == X86_OP_IMM && encoding.imm_size >= 4 && !IsX86Branch(flow)) {
            const uint64 value = static_cast<uint64>(op.imm) & (is64 ? UINT64_MAX : 0xFFFFFFFFull);
            if (value >= 0x10000 && (!is64 || encoding.imm_size == 8)) // push offset aText / mov ecx, 0x403000 / movabs rax, address
                MaskRange(masked, encoding.imm_offset, encoding.imm_size);
        }
    }
}

// ARM64: the whole instruction of bl / b, adrp / adr, the literal loads and the instructions of the adrp pairs
bool IsArm64AddressInstruction(const cs_insn& insn, const DissasmCodeZone& zone)
{
    if (insn.id == 0 || !insn.detail)
        return false;
    if (zone.resolvedAddresses.contains(insn.address))
        return true;
    const cs_arm64& arm64 = insn.detail->arm64;
    switch (insn.id) {
    case ARM64_INS_BL:
    case ARM64_INS_ADRP:
    case ARM64_INS_ADR:
        return true;
    case ARM64_INS_B:
        return std::string_view(insn.mnemonic) == "b"; // b.cond stays (inside the function)
    case ARM64_INS_LDR:
    case ARM64_INS_LDRSW:
        return arm64.op_count == 2 && arm64.operands[1].type == ARM64_OP_IMM;
    default:
        return false;
    }
}

// 32 bit ARM: the whole instruction of bl / blx / b, movw / movt, the literal loads, the addresses built in the registers; the literal
// pools (the data lines of the function hold addresses)
bool IsArm32AddressInstruction(const cs_insn& insn, const DissasmCodeZone& zone)
{
    if (insn.id == 0 || !insn.detail)
        return true; // a literal pool
    if (zone.resolvedAddresses.contains(insn.address))
        return true;
    const std::string_view mnemonic = insn.mnemonic;
    const cs_arm& arm               = insn.detail->arm;
    switch (insn.id) {
    case ARM_INS_BL:
    case ARM_INS_BLX:
    case ARM_INS_MOVW:
    case ARM_INS_MOVT:
        return true;
    case ARM_INS_B:
        return mnemonic == "b" || mnemonic == "b.w";
    case ARM_INS_MOV:
        return mnemonic.starts_with("movw");
    default:
        break;
    }
    for (uint8 index = 0; index < arm.op_count; index++)
        if (arm.operands[index].type == ARM_OP_MEM && arm.operands[index].mem.base == ARM_REG_PC)
            return true; // ldr r0, [pc, #off]
    return false;
}

// "55 48 ?? E5" -> 0x55, 0x48, MASKED, 0xE5; none when a token is not a byte
std::optional<std::vector<int16>> ParsePattern(std::string_view text)
{
    std::vector<int16> tokens;
    size_t position = 0;
    while (position < text.size()) {
        if (text[position] == ' ') {
            position++;
            continue;
        }
        if (position + 2 > text.size())
            return {};
        const auto token = text.substr(position, 2);
        if (token == "??")
            tokens.push_back(MASKED);
        else {
            int16 value = 0;
            for (const char c : token) {
                value <<= 4;
                if (c >= '0' && c <= '9')
                    value |= c - '0';
                else if (c >= 'A' && c <= 'F')
                    value |= c - 'A' + 10;
                else if (c >= 'a' && c <= 'f')
                    value |= c - 'a' + 10;
                else
                    return {};
            }
            tokens.push_back(value);
        }
        position += 2;
    }
    return tokens;
}

std::vector<int16> PatternTokens(const DissasmFunctionPattern& pattern)
{
    std::vector<int16> tokens(pattern.bytes.size());
    for (size_t index = 0; index < tokens.size(); index++)
        tokens[index] = pattern.masked[index] ? MASKED : static_cast<int16>(pattern.bytes[index]);
    return tokens;
}

std::string TokensKey(const std::vector<int16>& tokens)
{
    std::string key;
    for (size_t index = 0; index < KEY_TOKENS && index < tokens.size(); index++) {
        key.push_back(static_cast<char>(tokens[index] & 0xFF));
        key.push_back(tokens[index] == MASKED ? '?' : '.');
    }
    return key;
}
} // namespace

std::string DissasmFunctionPattern::ToText() const
{
    std::string text;
    text.reserve(bytes.size() * 3);
    char value[4];
    for (size_t index = 0; index < bytes.size(); index++) {
        if (index > 0)
            text.push_back(' ');
        if (masked[index])
            text.append("??");
        else {
            snprintf(value, sizeof(value), "%02X", bytes[index]);
            text.append(value);
        }
    }
    return text;
}

uint32 DissasmFunctionPattern::FixedBytes() const
{
    return static_cast<uint32>(std::count(masked.begin(), masked.end(), false));
}

std::optional<DissasmFunctionPattern> GView::View::DissasmViewer::BuildFunctionPattern(DissasmCodeZone& zone, uint64 start)
{
    if (!zone.CanReachAsmLines() || zone.cachedCodeOffsets.empty())
        return {};
    const uint64 codeSize = zone.GetCodeSize();
    if (start >= codeSize)
        return {};
    const auto next  = std::upper_bound(zone.functionStarts.begin(), zone.functionStarts.end(), start);
    const uint64 end = std::min<uint64>(next != zone.functionStarts.end() ? *next : codeSize, codeSize);
    if (end <= start)
        return {};
    const csh handle = zone.GetDecodeHandle();
    if (handle == 0)
        return {};
    cs_insn* insn = cs_malloc(handle);
    if (!insn)
        return {};

    DissasmFunctionPattern pattern;
    pattern.functionSize    = end - start;
    size_t codeEnd          = 0; // the pattern bytes up to the last instruction that is not padding
    const uint64 patternEnd = std::min<uint64>(end, start + DISSASM_SIGNATURE_MAX_SIZE);
    DissasmCodeLinesWalker walker(
          zone.zoneObject, zone.cachedCodeOffsets[0].offset, codeSize, handle, start, &zone.instructionBoundaries, zone.paddingAlignmentBase, &zone.instructionSet);
    while (walker.GetAddress() < patternEnd && walker.Next(insn)) {
        if (insn->size > sizeof(insn->bytes))
            break; // a long align line: the padding after the code
        const size_t size = insn->size;
        std::vector<bool> masked(size, false);
        const auto arch = zone.GetArchAt(insn->address);
        if (arch == DissasmArch::X86 || arch == DissasmArch::X64)
            MaskX86(*insn, arch == DissasmArch::X64, masked);
        else if (arch == DissasmArch::Arm64 ? IsArm64AddressInstruction(*insn, zone) : IsArm32AddressInstruction(*insn, zone))
            masked.assign(size, true);
        for (size_t index = 0; index < size && insn->address + index < patternEnd; index++) {
            pattern.bytes.push_back(insn->bytes[index]);
            pattern.masked.push_back(masked[index]);
        }
        if (GetInstructionKind(insn->id, insn->mnemonic, arch) != X86InstructionKind::Padding)
            codeEnd = pattern.bytes.size();
    }
    cs_free(insn, 1);
    // the padding after the code (int3 / nop / align up to the next function) is not part of the pattern: a short function would match
    // every function of the same size with the same few bytes
    pattern.bytes.resize(codeEnd);
    pattern.masked.resize(codeEnd);
    zone.asmPreCacheData.Clear(); // the decoding position of the drawn lines moved
    if (pattern.bytes.empty())
        return {};
    return pattern;
}

json GView::View::DissasmViewer::BuildSignaturesDocument(const std::vector<DissasmCodeZone*>& zones)
{
    json document = { { "format", DISSASM_SIGNATURES_FORMAT },
                      { "version", DISSASM_SIGNATURES_VERSION },
                      { "architecture", zones.empty() ? std::string_view() : ArchitectureFamily(*zones.front()) } };
    json signatures = json::array();
    std::unordered_set<std::string> names;
    for (auto* zone : zones) {
        if (ArchitectureFamily(*zone) != ArchitectureFamily(*zones.front()))
            continue;
        for (const uint64 start : zone->functionStarts) {
            const std::string name = zone->GetLabelNameAt(start);
            if (IsAutomaticName(name) || names.contains(name))
                continue;
            const auto pattern = BuildFunctionPattern(*zone, start);
            if (!pattern.has_value() || pattern->FixedBytes() < DISSASM_SIGNATURE_MIN_FIXED_BYTES)
                continue; // not specific enough
            names.insert(name);
            signatures.push_back({ { "name", name },
                                   { "size", pattern->functionSize <= DISSASM_SIGNATURE_MAX_SIZE ? pattern->functionSize : 0 },
                                   { "pattern", pattern->ToText() } });
        }
    }
    document["signatures"] = std::move(signatures);
    return document;
}

bool GView::View::DissasmViewer::ApplySignaturesDocument(
      const json& document, const std::vector<DissasmCodeZone*>& zones, DissasmSignaturesApply& result, std::string& error)
{
    if (!document.is_object() || document.value("format", std::string()) != DISSASM_SIGNATURES_FORMAT) {
        error = "This is not a GView signatures file!";
        return false;
    }
    if (!document.contains("version") || !document["version"].is_number_unsigned() || document["version"].get<uint64>() > DISSASM_SIGNATURES_VERSION) {
        error = "The signatures file was written by a newer GView!";
        return false;
    }
    const auto architecture = document.value("architecture", std::string());

    struct Signature {
        std::string name;
        uint64 size;
        std::vector<int16> tokens;
    };
    std::vector<Signature> signatures;
    std::unordered_map<std::string, std::vector<size_t>> index;
    if (document.contains("signatures") && document["signatures"].is_array())
        for (const auto& item : document["signatures"]) {
            if (!item.is_object() || !item.contains("name") || !item["name"].is_string() || !item.contains("pattern") || !item["pattern"].is_string())
                continue;
            auto name   = item["name"].get<std::string>();
            auto tokens = ParsePattern(item["pattern"].get<std::string>());
            if (name.empty() || name.size() > MAX_NAME_SIZE || !tokens.has_value() || tokens->size() < KEY_TOKENS ||
                tokens->size() > DISSASM_SIGNATURE_MAX_SIZE)
                continue;
            const uint64 size = item.contains("size") && item["size"].is_number_unsigned() ? item["size"].get<uint64>() : 0;
            index[TokensKey(tokens.value())].push_back(signatures.size());
            signatures.push_back({ std::move(name), size, std::move(tokens.value()) });
        }
    result.signatures = static_cast<uint32>(signatures.size());

    bool hasZone = false;
    for (auto* zone : zones) {
        if (ArchitectureFamily(*zone) != architecture)
            continue;
        hasZone = true;
        // the name of every function with an automatic name that matches the signatures of one name only
        std::vector<std::pair<uint64, std::string>> matches;
        std::unordered_map<std::string, uint32> functionsOfName;
        for (const uint64 start : zone->functionStarts) {
            if (!zone->GetLabelNameAt(start).starts_with("sub_"))
                continue;
            const auto pattern = BuildFunctionPattern(*zone, start);
            if (!pattern.has_value())
                continue;
            const auto tokens    = PatternTokens(pattern.value());
            const auto candidate = index.find(TokensKey(tokens));
            if (candidate == index.end())
                continue;
            std::unordered_set<std::string_view> names;
            for (const size_t signatureIndex : candidate->second) {
                const auto& signature = signatures[signatureIndex];
                if (signature.tokens.size() > tokens.size())
                    continue;
                if (signature.size != 0 ? pattern->functionSize != signature.size : pattern->functionSize <= DISSASM_SIGNATURE_MAX_SIZE)
                    continue; // a whole function of another size / a long function against a short one
                if (std::equal(signature.tokens.begin(), signature.tokens.end(), tokens.begin()))
                    names.insert(signature.name);
            }
            if (names.size() == 1) {
                matches.emplace_back(start, std::string(*names.begin()));
                functionsOfName[matches.back().second]++;
            } else if (names.size() > 1)
                result.ambiguous++;
        }
        bool renamed = false;
        for (const auto& [start, name] : matches) {
            if (functionsOfName[name] != 1) {
                result.ambiguous++;
                continue;
            }
            if (zone->FindLabelByName(name).has_value())
                continue; // the name is used already
            if (zone->ApplyUserLabelName(start, name)) {
                result.named++;
                renamed = true;
            }
        }
        if (renamed) {
            zone->ClearEditHistory(); // the names are not edits that can be undone
            zone->asmPreCacheData.Clear();
        }
    }
    if (!hasZone) {
        error = "The signatures are for " + architecture + " code: no disassembly zone of this file has it!";
        return false;
    }
    return true;
}
