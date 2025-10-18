import math

def safe_char(c):
    turkish_chars = "çğıöşüÇĞİÖŞÜ"
    return c if c in turkish_chars else None

def normalize_text(text):
    mapping = str.maketrans("ığüşöçİĞÜŞÖÇ", "igusocIGUSOC")
    return text.translate(mapping)

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if safe_char(char):
            result += char
        elif char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift)

def vigenere_encrypt(text, key):
    text = normalize_text(text)
    key = normalize_text(key.lower())
    result = ""
    key_index = 0
    for char in text:
        if safe_char(char):
            result += char
        elif char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(cipher, key):
    cipher = normalize_text(cipher)
    key = normalize_text(key.lower())
    result = ""
    key_index = 0
    for char in cipher:
        if safe_char(char):
            result += char
        elif char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result

def substitution_encrypt(text, key_map):
    result = ""
    for char in text.lower():
        if safe_char(char):
            result += char
        elif char in key_map:
            result += key_map[char]
        else:
            result += char
    return result

def substitution_decrypt(cipher, key_map):
    rev_map = {v: k for k, v in key_map.items()}
    return substitution_encrypt(cipher, rev_map)

def affine_encrypt(text, a, b):
    if math.gcd(a, 26) != 1:
        raise ValueError("a değeri 26 ile aralarında asal olmalı")
    result = ""
    for char in text:
        if safe_char(char):
            result += char
        elif char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr(((a * (ord(char) - ord(base)) + b) % 26) + ord(base))
        else:
            result += char
    return result

def affine_decrypt(cipher, a, b):
    if math.gcd(a, 26) != 1:
        raise ValueError("a değeri 26 ile aralarında asal olmalı")
    result = ""
    try:
        a_inv = pow(a, -1, 26)
    except ValueError:
        raise ValueError("a değeri için mod ters hesaplanamadı")
    for char in cipher:
        if safe_char(char):
            result += char
        elif char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((a_inv * ((ord(char) - ord(base) - b)) % 26) + ord(base))
        else:
            result += char
    return result

def prepare_playfair_matrix(key):
    key = normalize_text(key.lower().replace("j", "i"))
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    seen = set()
    matrix = []
    for char in key + alphabet:
        if char not in seen and char.isalpha():
            seen.add(char)
            matrix.append(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None, None

def playfair_prepare_text(text):
    text = normalize_text(text.lower().replace("j", "i"))
    cleaned = [c for c in text if c.isalpha()]
    pairs = []
    i = 0
    while i < len(cleaned):
        a = cleaned[i]
        b = ''
        if i + 1 < len(cleaned):
            b = cleaned[i + 1]
        if a == b:
            pairs.append((a, 'x'))
            i += 1
        else:
            if b:
                pairs.append((a, b))
                i += 2
            else:
                pairs.append((a, 'x'))
                i += 1
    return pairs

def playfair_encrypt(text, key):
    matrix = prepare_playfair_matrix(key)
    pairs = playfair_prepare_text(text)
    result = ""
    for a, b in pairs:
        row_a, col_a = playfair_find_position(matrix, a)
        row_b, col_b = playfair_find_position(matrix, b)
        if row_a == row_b:
            result += matrix[row_a][(col_a + 1) % 5]
            result += matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            result += matrix[(row_a + 1) % 5][col_a]
            result += matrix[(row_b + 1) % 5][col_b]
        else:
            result += matrix[row_a][col_b]
            result += matrix[row_b][col_a]
    return result.upper()

def playfair_decrypt(cipher, key):
    matrix = prepare_playfair_matrix(key)
    cipher = normalize_text(cipher.lower().replace("j", "i"))
    pairs = [(cipher[i], cipher[i + 1]) for i in range(0, len(cipher), 2)]
    result = ""
    for a, b in pairs:
        row_a, col_a = playfair_find_position(matrix, a)
        row_b, col_b = playfair_find_position(matrix, b)
        if row_a == row_b:
            result += matrix[row_a][(col_a - 1) % 5]
            result += matrix[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            result += matrix[(row_a - 1) % 5][col_a]
            result += matrix[(row_b - 1) % 5][col_b]
        else:
            result += matrix[row_a][col_b]
            result += matrix[row_b][col_a]
    return result.upper()
def rail_fence_encrypt(text, key):
    if not isinstance(key, int) or key <= 1 or len(text) <= 1:
        return text
    rails = ['' for _ in range(key)]
    direction_down = False
    row = 0
    for char in text:
        rails[row] += char
        if row == 0 or row == key - 1:
            direction_down = not direction_down
        row += 1 if direction_down else -1
    return ''.join(rails)



def rail_fence_decrypt(cipher, key):
    if not isinstance(key, int) or key <= 1 or len(cipher) <= 1:
        return cipher
    if not isinstance(key, int) or key <= 1:
        raise ValueError("Anahtar (satır sayısı) 2 veya daha büyük bir tam sayı olmalıdır")
    rail_pattern = []
    direction_down = None
    row = 0
    for _ in range(len(cipher)):
        rail_pattern.append(row)
        if row == 0:
            direction_down = True
        elif row == key - 1:
            direction_down = False
        row += 1 if direction_down else -1
    rails = ['' for _ in range(key)]
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail_pattern[j] == i:
                rails[i] += cipher[index]
                index += 1
    result = ''
    rail_pos = [0] * key
    row = 0
    for i in range(len(cipher)):
        result += rails[row][rail_pos[row]]
        rail_pos[row] += 1
        if row == 0:
            direction_down = True
        elif row == key - 1:
            direction_down = False
        row += 1 if direction_down else -1
    return result

def route_encrypt(text, cols, clockwise=True):
    text = text.replace(" ", "").upper()
    if not cols or cols <= 0:
        return text
    rows = (len(text) + cols - 1) // cols
    matrix = [["X" for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(text):
                matrix[r][c] = text[idx]
                idx += 1

    result = []
    top, left = 0, 0
    bottom, right = rows - 1, cols - 1

    while top <= bottom and left <= right:
        for c in range(right, left - 1, -1):
            result.append(matrix[top][c])
        top += 1
        for r in range(top, bottom + 1):
            result.append(matrix[r][left])
        left += 1
        if top <= bottom:
            for c in range(left, right + 1):
                result.append(matrix[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(matrix[r][right])
            right -= 1
    return "".join(result)


def route_decrypt(cipher, cols, clockwise=True):
    if not cols or cols <= 0:
        return cipher
    text = list(cipher)
    rows = (len(cipher) + cols - 1) // cols
    matrix = [["" for _ in range(cols)] for _ in range(rows)]
    top, left = 0, 0
    bottom, right = rows - 1, cols - 1
    idx = 0

    while top <= bottom and left <= right:
        for c in range(right, left - 1, -1):
            if idx < len(cipher):
                matrix[top][c] = text[idx]
                idx += 1
        top += 1
        for r in range(top, bottom + 1):
            if idx < len(cipher):
                matrix[r][left] = text[idx]
                idx += 1
        left += 1
        if top <= bottom:
            for c in range(left, right + 1):
                if idx < len(cipher):
                    matrix[bottom][c] = text[idx]
                    idx += 1
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if idx < len(cipher):
                    matrix[r][right] = text[idx]
                    idx += 1
            right -= 1

    result = []
    for r in range(rows):
        for c in range(cols):
            result.append(matrix[r][c])
    return "".join(result)
