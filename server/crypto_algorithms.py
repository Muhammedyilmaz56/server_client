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
