def decodeChars(characteristics):
    rwe = ''
    if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
        rwe += 'R'
    else:
        rwe += ' '
    if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
        rwe += 'W'
    else:
        rwe += ' '
    if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        rwe += 'E'
    else:
        rwe += ' '
    return rwe