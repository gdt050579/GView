def GetCharTypeSQL(ch):
    if ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_":
        return "Word"
    if ch in "0123456789":
        return "Number"

    if ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r':
        return "Space"

    if ch == '#':
        return "Operator"

    # Operators and punctuation that participate in multi-char tokens:
    #  - comparisons: < > = ! (for !=)
    #  - arithmetic: + - * / %
    #  - concat: ||
    #  - casts: ::
    #  - JSON ops: -> ->>
    #  - parameter markers: ? : @ $
    #  - dot qualifier: .
    if ch in "!%+-=^&|*:?~\\/><.@$":
        return "Operator"

    if ch == '{':
        return "BlockOpen"
    if ch == '}':
        return "BlockClose"

    if ch == '[':
        return "ArrayOpen"
    if ch == ']':
        return "ArrayClose"

    # Parentheses
    if ch == '(':
        return "ExpressionOpen"
    if ch == ')':
        return "ExpressionClose"

    # Separators
    if ch == ',':
        return "Comma"
    if ch == ';':
        return "Semicolumn"

    # Quotes:
    if ch == '"' or ch == "'" or ch == '`':
        return "String"

    return "Invalid"


s = "uint8 Sql_Groups_IDs[] = {"
for i in range(0, 128):
    s += GetCharTypeSQL(chr(i)) + ","
s = s[:-1] + "};"
print(s)
