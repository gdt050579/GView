rule find_integer_2 {
    meta:
        description = "Matches x86 opcode sequence for mov dword ptr [ebp-?], 2"

    strings:
        $mov_i_2 = { C7 45 ?? 02 00 00 00 }
        
    condition:
        $mov_i_2

}
    