"""Independent translation of the firmware's initialized-data decompressor."""

def decompress_initializer(firmware):
    position = 0x1c43c
    result = bytearray()

    def take():
        nonlocal position
        value = firmware[position]
        position += 1
        return value

    while len(result) < 0x7a8:
        flags = take()
        literals = flags & 7
        if literals == 0:
            literals = take()
        count = flags >> 4
        if count == 0:
            count = take()
        for _ in range(literals - 1):
            result.append(take())
        if flags & 8:
            offset = take()
            for _ in range(count + 2):
                result.append(result[-offset])
        else:
            result.extend(bytes(count))
    assert len(result) == 0x7a8
    return bytes(result)
