# -*- coding: utf-8 -*-

# ====== SEZAR ŞİFRELEME ======
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
        else:
            result += char
    return result

def caesar_decrypt(cipher, shift):
    return caesar_encrypt(cipher, -shift)


# ====== VIGENERE ŞİFRELEME ======
def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    j = 0
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            shift = ord(key[j % len(key)]) - ord('a')
            result += chr((ord(char) - ord(base) + shift) % 26 + ord(base))
            j += 1
        else:
            result += char
    return result

def vigenere_decrypt(cipher, key):
    result = ""
    key = key.lower()
    j = 0
    for char in cipher:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            shift = ord(key[j % len(key)]) - ord('a')
            result += chr((ord(char) - ord(base) - shift) % 26 + ord(base))
            j += 1
        else:
            result += char
    return result


# ====== SUBSTITUTION ŞİFRELEME ======
def substitution_encrypt(text, key_map):
    result = ""
    for char in text.lower():
        if char in key_map:
            result += key_map[char]
        else:
            result += char
    return result

def substitution_decrypt(cipher, key_map):
    rev_map = {v: k for k, v in key_map.items()}
    return substitution_encrypt(cipher, rev_map)


# ====== AFFINE ŞİFRELEME ======
def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr(((a * (ord(char) - ord(base)) + b) % 26) + ord(base))
        else:
            result += char
    return result

def affine_decrypt(cipher, a, b):
    result = ""
    a_inv = pow(a, -1, 26)  # mod 26 tersini bul
    for char in cipher:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr(((a_inv * ((ord(char) - ord(base) - b)) % 26) + ord(base)))
        else:
            result += char
    return result
