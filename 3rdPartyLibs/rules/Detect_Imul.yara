import "pe"

rule Detect_IMUL_Instruction
{
    meta:
        description = "Detecteaza instructiuni IMUL (x86)"

    strings:
        $imul_standard_2ops = { 0F AF ?? ?? } // imul reg, [mem]
        $imul_triple_with_byte = { 6B (C? | D? | E? | F?) ?? } // imul reg, reg, imm8

    condition:
        pe.is_pe and any of them in (
        pe.sections[pe.section_index(".text")].raw_data_offset .. 
        pe.sections[pe.section_index(".text")].raw_data_offset + 
        pe.sections[pe.section_index(".text")].raw_data_size
    )
}