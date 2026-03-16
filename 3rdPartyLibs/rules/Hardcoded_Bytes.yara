rule Hardcoded_Bytes {
    meta:
        description = "Detects hardcoded byte pattern "
        severity = "high"

    strings:
        $xor = { 1F 0A 1F 0A }

    condition:
        $xor
}