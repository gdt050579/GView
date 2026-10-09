rule C2_Beacon {
    meta:
        description = "Identifies indicators of simple HTTP-based C2 beaconing"

    strings:
        $url = /http(s)?:\/\/.*\/api/
        $beacon = "beacon"

    condition:
        $url and $beacon
}
