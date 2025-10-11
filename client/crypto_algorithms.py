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
