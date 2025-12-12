import math
import os
from des_from_scratch import des_encrypt_message, des_decrypt_message

from des_with_library import des_encrypt_message_lib, des_decrypt_message_lib
from aes_from_scratch import aes_encrypt_message, aes_decrypt_message
from aes_with_library import aes_encrypt_message_lib, aes_decrypt_message_lib

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
def columnar_encrypt(text, key):
    text = text.replace(" ", "").upper()
    key = key.upper()
    cols = len(key)
    rows = (len(text) + cols - 1) // cols
    matrix = [["X" for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(text):
                matrix[r][c] = text[idx]
                idx += 1
    key_order = sorted(list(key))
    order = [key_order.index(k) + 1 for k in key]
    result = ""
    for num in sorted(order):
        col = order.index(num)
        for r in range(rows):
            result += matrix[r][col]
    return result


def columnar_decrypt(cipher, key):
    key = key.upper()
    cols = len(key)
    rows = (len(cipher) + cols - 1) // cols
    key_order = sorted(list(key))
    order = [key_order.index(k) + 1 for k in key]
    matrix = [["" for _ in range(cols)] for _ in range(rows)]
    col_lengths = [rows] * cols
    idx = 0
    for num in sorted(order):
        col = order.index(num)
        for r in range(col_lengths[col]):
            if idx < len(cipher):
                matrix[r][col] = cipher[idx]
                idx += 1
    result = ""
    for r in range(rows):
        for c in range(cols):
            result += matrix[r][c]
    return result
def polybius_encrypt(text):
    text = normalize_text(text).upper().replace("J", "I").replace(" ", "")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    grid = {alphabet[i]: divmod(i, 5) for i in range(25)}
    out = []
    for ch in text:
        if ch in grid:
            r, c = grid[ch]
            out.append(str(r + 1))
            out.append(str(c + 1))
        else:
            continue
    return "".join(out)


def polybius_decrypt(cipher):
    cipher = cipher.replace(" ", "")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    out = []
    i = 0
    while i < len(cipher):
        if i + 1 < len(cipher) and cipher[i].isdigit() and cipher[i + 1].isdigit():
            r = int(cipher[i])
            c = int(cipher[i + 1])
            idx = (r - 1) * 5 + (c - 1)
            if 0 <= idx < 25:
                out.append(alphabet[idx])
            i += 2
        else:
            i += 1
    return "".join(out)
def pigpen_encrypt(text):
    base_path = "static/pigpen"
    text = text.upper().replace(" ", "")
    result = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            result.append(f"/{base_path}/{ch}.png")
    return "|".join(result)

def pigpen_decrypt(cipher):
    parts = cipher.split("|")
    result = ""
    for p in parts:
        if p.strip():
            ch = p.split("/")[-1].split(".")[0]
            result += ch
    return result


def _hill_parse_key(key_str):
    """
    key_str: 2x2 matris için 4 sayı (virgül veya boşlukla ayrılmış)
    Örn: "3 3 2 5" veya "3,3,2,5"
    """
    parts = key_str.replace(",", " ").split()
    if len(parts) != 4:
        raise ValueError("Hill anahtarı 4 sayı içermeli (2x2 matris). Örn: '3 3 2 5'")

    nums = []
    for p in parts:
        if not p.lstrip("-").isdigit():
            raise ValueError("Hill anahtarı sadece tam sayılardan oluşmalıdır.")
        nums.append(int(p) % 26)

    a, b, c, d = nums
    det = (a * d - b * c) % 26
    if math.gcd(det, 26) != 1:
        raise ValueError("Geçersiz Hill anahtarı: determinant 26 ile aralarında asal olmalı.")
    return a, b, c, d


def _hill_inverse_matrix(a, b, c, d):
    det = (a * d - b * c) % 26
    det_inv = pow(det, -1, 26)  
    ia = ( det_inv * d) % 26
    ib = (-det_inv * b) % 26
    ic = (-det_inv * c) % 26
    id = ( det_inv * a) % 26
    return ia, ib, ic, id


def hill_encrypt(text, key):
  
    a, b, c, d = _hill_parse_key(key)
    text = normalize_text(text).lower()
    letters = [ch for ch in text if ch.isalpha()]

    
    if len(letters) % 2 == 1:
        letters.append('x')

    result = []
    for i in range(0, len(letters), 2):
        p0 = ord(letters[i])   - ord('a')
        p1 = ord(letters[i+1]) - ord('a')
        c0 = (a * p0 + b * p1) % 26
        c1 = (c * p0 + d * p1) % 26
        result.append(chr(c0 + ord('A')))
        result.append(chr(c1 + ord('A')))
    return "".join(result)


def hill_decrypt(cipher, key):
   
    a, b, c, d = _hill_parse_key(key)
    ia, ib, ic, id = _hill_inverse_matrix(a, b, c, d)

    cipher = normalize_text(cipher).lower()
    letters = [ch for ch in cipher if ch.isalpha()]

  
    if len(letters) % 2 == 1:
        letters.append('x')

    result = []
    for i in range(0, len(letters), 2):
        c0 = ord(letters[i])   - ord('a')
        c1 = ord(letters[i+1]) - ord('a')
        p0 = (ia * c0 + ib * c1) % 26
        p1 = (ic * c0 + id * c1) % 26
        result.append(chr(p0 + ord('A')))
        result.append(chr(p1 + ord('A')))
    return "".join(result)

