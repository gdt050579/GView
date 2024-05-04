buffer = ''

buffer += ''.join(chr(c) for c in range(ord('A'), ord('Z') + 1))
buffer += ''.join(chr(c) for c in range(ord('a'), ord('z') + 1))
buffer += ''.join(chr(c) for c in range(ord('0'), ord('9') + 1))
buffer += '+/'

# encode table
print('encode table:')
print('{ ' + ', '.join(f'\'{c}\'' for c in buffer) + ' }')


# decode table

mapping = {c: i for i, c in enumerate(buffer)}

max_char = max(mapping.keys(), key=lambda c: ord(c))

print('decode table:')
print('{' + ', '.join(f'{mapping.get(chr(c), -1)}' for c in range(ord(max_char) + 1)) + '}')
