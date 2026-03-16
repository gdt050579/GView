rule hello_world_str {

    meta:
        description = "A simple proof-of-concept to show YARA rules"
        author = "Carcea Razvan"

    strings:
        $hello = "Hello World!"

    condition:
        $hello

}