# -*- coding: utf-8 -*-
import math
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
# Türkçe karakter dönüşüm tablosu
def normalize_text(text):
    mapping = str.maketrans("ığüşöçİĞÜŞÖÇ", "igusocIGUSOC")
    return text.translate(mapping)

# ====== VIGENERE ŞİFRELEME ======
def vigenere_encrypt(text, key):
    text = normalize_text(text)
    key = normalize_text(key.lower())
    result = ""
    key_index = 0

    for char in text:
        if char.isalpha():
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
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('a')
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
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
    # a ile 26 aralarında asal mı kontrol et
    if math.gcd(a, 26) != 1:
        raise ValueError("a değeri 26 ile aralarında asal olmalı (örnek: 3, 5, 7, 9, 11...)")

    result = ""
    for char in text:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr(((a * (ord(char) - ord(base)) + b) % 26) + ord(base))
        else:
            result += char
    return result


def affine_decrypt(cipher, a, b):
    if math.gcd(a, 26) != 1:
        raise ValueError("a değeri 26 ile aralarında asal olmalı (örnek: 3, 5, 7, 9, 11...)")

    result = ""
    try:
        a_inv = pow(a, -1, 26)  # mod 26'da tersini bul
    except ValueError:
        raise ValueError("a değeri için mod ters hesaplanamadı — 26 ile aralarında asal olduğuna emin ol.")

    for char in cipher:
        if char.isalpha():
            base = 'A' if char.isupper() else 'a'
            result += chr(((a_inv * ((ord(char) - ord(base) - b)) % 26) + ord(base)))
        else:
            result += char
    return result