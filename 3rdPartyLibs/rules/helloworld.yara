rule hello_str : test demo poc{

    meta:
        description = "A simple proof-of-concept to show YARA rules"
        author = "Carcea Razvan"
        severity = "low"


    strings:
        $hello = "Hello"
        $world = "World"

    condition:
        $hello or $world

}

rule world_str : malware demo{

    meta:
        description = "Demo"
        author = "Carcea Diana"
        severity = "high"


    strings:
        $world = "World"

    condition:
        $world

}