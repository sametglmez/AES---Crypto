import binascii
import copy
import hashlib

import numpy as np
import codecs
import sys

Rcon= [
     0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d]

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)



def convertStringToHex(str):
    result = bytes(str, "utf-8")

    output = binascii.hexlify(result)
    assert len(str) == 16
    return output

def bytes2matrix(text):
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def expandKey(master_key):
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}
    n_rounds = rounds_by_key_size[len(master_key)]
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4
    columns_per_iteration = len(key_columns)
    i = 1

    while len(key_columns) < (n_rounds + 1) * 4:
        word = list(key_columns[-1])

        if len(key_columns) % iteration_size == 0:
            word.append(word.pop(0))
            word = [s_box[b] for b in word]
            word[0] ^= Rcon[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            word = [s_box[b] for b in word]

        word = xor_bytes(word, key_columns[-iteration_size])
        key_columns.append(word)

    return [key_columns[4 * i: 4 * (i + 1)] for i in range(len(key_columns) // 4)]

def print_matrix(m):
    round = 0
    for i in m:
        print('Round {:2}:'.format(round), end=' ')
        for j in i:
            print('{}'.format(' '.join("{:02X}".format(x) for x in j)), end=' ')
        round += 1
        print(" ")

    #print(m[0])

def add_round_key(s, k):
    result = [["0"] * 4 for i in range(4)]
    #print(int("6E", 16))  # str-hex to int
    for i in range(4):
        for j in range(4):
            result[i][j] = int(s[i][j],16) ^ int(k[i][j],16)

    return result

def intToStringHex(s):
    index = 0
    result = [["0"] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = "0x{:02x}".format(s[i][j])
            index += 1

    return result

def sub_sbox(s):
    result = [["0"] * 4 for i in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = s_box[s[i][j]]

    return result

def shift_rows(s):
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]


def galois_mult(a, b):

    p = 0
    hi_bit_set = 0
    for i in range(8):
        if b & 1 == 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set == 0x80: a ^= 0x1b
        b >>= 1
    return p % 256

def mix_column(column):

    temp = copy.copy(column)
    column[0] = galois_mult(temp[0], 2) ^ galois_mult(temp[1], 3) ^ \
                galois_mult(temp[2], 1) ^ galois_mult(temp[3], 1)
    column[1] = galois_mult(temp[0], 1) ^ galois_mult(temp[1], 2) ^ \
                galois_mult(temp[2], 3) ^ galois_mult(temp[3], 1)
    column[2] = galois_mult(temp[0], 1) ^ galois_mult(temp[1], 1) ^ \
                galois_mult(temp[2], 2) ^ galois_mult(temp[3], 3)
    column[3] = galois_mult(temp[0], 3) ^ galois_mult(temp[1], 1) ^ \
                galois_mult(temp[2], 1) ^ galois_mult(temp[3], 2)

def mix_columns(state, nb):

    for i in range(nb):
        column = []
        for j in range(nb): column.append(state[j][i])
        mix_column(column)

        for j in range(nb): state[j][i] = column[j]

def mixColumnInv(column):
    temp =copy.copy(column)
    column[0] = galois_mult(temp[0],14) ^ galois_mult(temp[3],9) ^ \
                galois_mult(temp[2],13) ^ galois_mult(temp[1],11)
    column[1] = galois_mult(temp[1],14) ^ galois_mult(temp[0],9) ^ \
                galois_mult(temp[3],13) ^ galois_mult(temp[2],11)
    column[2] = galois_mult(temp[2],14) ^ galois_mult(temp[1],9) ^ \
                galois_mult(temp[0],13) ^ galois_mult(temp[3],11)
    column[3] = galois_mult(temp[3],14) ^ galois_mult(temp[2],9) ^ \
                galois_mult(temp[1],13) ^ galois_mult(temp[0],11)

def mixColumnsInv(state):
    for i in range(4):
        column = []
        for j in range(4):
            column.append(state[j][i])

        mixColumnInv(column)

        for j in range(4):


            state[j][i] = column[j]

def shift_rowsInv(s):
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]

def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]
    return s

def encrypt(plaintextMatrixHex,result2,length):
    plaintextMatrixHex = add_round_key(plaintextMatrixHex, result2[0])

    for i in range(length):
        if i == 9:
            plaintextMatrixHex = sub_sbox(plaintextMatrixHex);

            shift_rows(plaintextMatrixHex)
            plaintextMatrixHex = intToStringHex(plaintextMatrixHex)
            plaintextMatrixHex = add_round_key(plaintextMatrixHex, result2[i + 1])
            return intToStringHex(plaintextMatrixHex)
            break


        plaintextMatrixHex = sub_sbox(plaintextMatrixHex);



        shift_rows(plaintextMatrixHex)

        mix_columns(plaintextMatrixHex, 4)
        plaintextMatrixHex = intToStringHex(plaintextMatrixHex)
        plaintextMatrixHex = add_round_key(plaintextMatrixHex, result2[i + 1])


def descrypt(plaintextMatrixHex,result2,length):
    counter = length
    for i in range(length):
        if counter == length:
            plaintextMatrixHex = add_round_key(plaintextMatrixHex, result2[counter])
            shift_rowsInv(plaintextMatrixHex)
            plaintextMatrixHex = inv_sub_bytes(plaintextMatrixHex)
            counter -= 1
            continue

        plaintextMatrixHex = intToStringHex(plaintextMatrixHex)
        plaintextMatrixHex = add_round_key(plaintextMatrixHex, result2[counter])
        mixColumnsInv(plaintextMatrixHex)

        shift_rowsInv(plaintextMatrixHex)
        plaintextMatrixHex = inv_sub_bytes(plaintextMatrixHex)


        counter -= 1

    plaintextMatrixHex = intToStringHex(plaintextMatrixHex)
    plaintextMatrixHex = add_round_key(plaintextMatrixHex, result2[counter])
    return plaintextMatrixHex

def pad(plaintextMatrixHex,nb):

    text_length = len(plaintextMatrixHex)
    state_length = nb ** 2


    diff = text_length % state_length
    if diff != 0: plaintextMatrixHex.extend([0] * (state_length - diff))


    states = [plaintextMatrixHex[x:x + state_length] for x in
              range(0, len(plaintextMatrixHex), state_length)]

    return states

def split_blocks(message, block_size=16):
    return [message[i:i + 16] for i in range(0, len(message), block_size)]

def encryp_CBC(plainText,key):
    plaintextHex = []
    plaintextMatrixHex = [["0"] * 4 for i in range(4)]
    blocks = []
    index = 0

    viText = "My vitext in cbc"

    vi = [["0"] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            vi[j][i] = hex(int(format(ord(viText[index]))))
            index += 1

    for i in range(len(plainText)):
        plaintextHex.append(hex(int(format(ord(plainText[i])))))


    previous = vi

    index = 0
    for plaintext_block in split_blocks(plaintextHex):
        for i in range(4):
            for j in range(4):
                plaintextMatrixHex[j][i] = plaintext_block[index]
                index = index +  1
        plaintextMatrixHex = add_round_key(plaintextMatrixHex, previous)

        # Intten string hex çevirme
        for k in range(4):
            for m in range(4):
                plaintextMatrixHex[m][k] = hex(plaintextMatrixHex[m][k])


        block = encrypt(plaintextMatrixHex,key,10)
        blocks.append(block)
        previous = block
        index = 0

    return blocks

def decryption_CBC(blocks,key):
    index = 0
    plaintextMatrixHex = [["0"] * 4 for i in range(4)]

    viText = "My vitext in cbc"

    vi = [["0"] * 4 for i in range(4)]


    for i in range(4):
        for j in range(4):
            vi[j][i] = hex(int(format(ord(viText[index]))))
            index += 1

    previous = vi
    resultBlocks = []
    for plaintext_block in blocks:
        plaintextMatrixHex = descrypt(plaintext_block, key, 10)

        for k in range(4):
            for m in range(4):
                plaintextMatrixHex[m][k] = hex(plaintextMatrixHex[m][k])
        block = add_round_key(plaintextMatrixHex, previous)
        for k in range(4):
            for m in range(4):
                plaintextMatrixHex[k][m] = hex(block[m][k])
        block = plaintextMatrixHex
        resultBlocks.append(block)
        previous = plaintext_block

    return resultBlocks

def encrypt_OFB(plainText,key):
    plaintextHex = []
    plaintextMatrixHex = [["0"] * 4 for i in range(4)]
    resultTemp = []
    returnResult = []
    blocks = []

    index = 0

    viText = "My vitext in cbc"

    vi = [["0"] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            vi[j][i] = hex(int(format(ord(viText[index]))))
            index += 1

    for i in range(len(plainText)):
        plaintextHex.append(hex(int(format(ord(plainText[i])))))

    previous = vi

    index = 0
    for plaintext_block in split_blocks(plaintextHex):
        for i in range(4):
            for j in range(4):
                plaintextMatrixHex[j][i] = plaintext_block[index]
                index = index + 1

        block = encrypt(previous, key, 10)
        plaintextMatrixHex = add_round_key(plaintextMatrixHex, block)
        index = 0
        result = [["0"] * 4 for i in range(4)]
        for k in range(4):
            for m in range(4):
                result[m][k] = hex(plaintextMatrixHex[m][k])

        temp = plaintextMatrixHex
        blocks.append(result)
        previous = block


    for i in range(len(blocks)):
        for j in range(len(blocks[i])):
            for k in range(len(blocks[i][j])):
                returnResult.append(blocks[i][j][k])

    return returnResult


def decryption_OFB(plainText,key):
    plaintextHex = []
    plaintextMatrixHex = [["0"] * 4 for i in range(4)]
    resultTemp = []
    returnResult = []
    blocks = []

    index = 0

    viText = "My vitext in cbc"

    vi = [["0"] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            vi[j][i] = hex(int(format(ord(viText[index]))))
            index += 1

    """for i in range(len(plainText)):
        plaintextHex.append(hex(int(format(ord(plainText[i])))))"""

    previous = vi

    index = 0
    for plaintext_block in split_blocks(plainText):
        for i in range(4):
            for j in range(4):
                plaintextMatrixHex[i][j] = plaintext_block[index]
                index = index + 1
        block = encrypt(previous, key, 10)
        plaintextMatrixHex = add_round_key(plaintextMatrixHex, block)
        index = 0
        result = [["0"] * 4 for i in range(4)]
        for k in range(4):
            for m in range(4):
                result[m][k] = hex(plaintextMatrixHex[m][k])

        blocks.append(result)
        previous = block


    for i in range(len(blocks)):
        for j in range(len(blocks[i])):
            for k in range(len(blocks[i][j])):
                returnResult.append(blocks[i][k][j])

    return returnResult

def file_Encrypt(filename,key):
    BLOCK_SIZE = 65536

    file_hash = hashlib.sha256()
    with open(filename, 'rb') as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(BLOCK_SIZE)

    print(file_hash.hexdigest())
    result = file_hash.hexdigest()
    qqint = []
    for i in range(len(result)):
        qqint.append(hex(int(format(ord(result[i])))))
    print("----------------HASH FıLE HEX------------------------")
    for i in range(len(qqint)):
        if i % 16 == 0 and i > 0:
            print("\n")
        print(qqint[i], end=" ")
    print("\n\n------------HASH ENCRYPT--------------------")
    sonuc = encryp_CBC(result, key)
    printHexMatrix(sonuc)

    file = open("file.txt", "rb")
    byte = file.read(1)
    file_byte = []
    while byte:
        file_byte.append(byte)
        byte = file.read(1)
    print("\n\n--------------------------READ FILE BYTE-------------------------\n")
    for i in range(len(file_byte)):
        print(file_byte[i],end= " ")
        if i % 16 == 0 and i > 0:
            print("\n")
    file.close()

    descryptHash = []
    for i in range(len(sonuc)):
        for j in range(len(sonuc[i])):
            for k in range(len(sonuc[i][j])):
                file_byte.append((sonuc[i][j][k]))

    print("\n\n-------------------SONUNA HASH EKLENMİŞ DOSYA --------------------\n", file_byte)

    descrypt_file(file_byte,key)


def descrypt_file(file,key):
    lenFile = len(file)
    hashFileLen = lenFile - 64
    fileResult = []
    matrix = []
    counter = 0
    for i in range(lenFile):
        file_hash = [["0"] * 4 for i in range(4)]
        for j in range(4):
            for k in range (4):
                file_hash[j][k] = file[hashFileLen+counter]
                counter += 1
        matrix.append(file_hash)

        if counter == 64:
            break

    for i in range(hashFileLen):
        fileResult.append(file[i])


    sonuc = decryption_CBC(matrix, key)
    print("\n\n------------HASH DESCRYPT--------------------")
    printHexMatrix(sonuc)
    controlChangesInFile(fileResult, sonuc)
    sonuc[0][0][0] = 5
    controlChangesInFile(fileResult,sonuc)

def controlChangesInFile(file,hash):
    BLOCK_SIZE = 65536
    hashFile = []
    firstHash = []

    file_hash = hashlib.sha256()
    for i in range (len(file)):
        hashFile.append(file_hash.update(file[i]))

    result = file_hash.hexdigest()
    qqint = []
    for i in range(len(result)):
        qqint.append(hex(int(format(ord(result[i])))))

    for i in range(len(hash)):
        for j in range(len(hash[i])):
            for k in range (len(hash[i][j])):
                firstHash.append(hash[i][j][k])
    print("Gönderilen dosyanın sonunda hash çıkartıldıktan sonra kalan halinin alınmış Hashi\n")
    for i in range(len(qqint)):
        if i % 16 == 0 and i > 0:
            print("\n")
        print(qqint[i], end=" ")
    #print(qqint)
    print("\n\nGönderilen dosyanın sonuna eklenmiş olan Hash\n")
    for i in range(len(firstHash)):
        if i % 16 == 0 and i > 0:
            print("\n")
        print(firstHash[i], end=" ")
    #print(firstHash)

    for i in range(len(firstHash)):
        if firstHash[i] != qqint[i] :
            print("\n\nDosya üzerinden değişiklik yapılmıştır !!!!\n\n")
            return 0

    print("\n\nDosya üzerinde değşiklik yapılmamıştır !!!!\n\n")
    return 1


def printHexMatrix(matrix):
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            for k in range(len(matrix[i][j])):
                print(matrix[i][j][k],end =  " "),
        print("\n")

def main():
    plainText = "samet gulmez 123"
    cbcPlainText = "Two One Nine TwoTwo One Nine TwoSamet Sulo Samet"
    result = convertStringToHex(plainText)
    index = 0
    plaintextMatrixHex = [["0"] * 4 for i in range(4)]

    for i in range(4):
        for j in range(4):
            plaintextMatrixHex[j][i] = hex(int(format(ord(plainText[index]))))
            index += 1

    #("PlainTextMatrixHex---> ",plaintextMatrixHex,"\n\n")

    print("Plain Text : " ,cbcPlainText)

    #-------------------------------------------------------------------------------------

    key = "Thats my key for"
    print("Key :        ", key)
    key = key.encode('utf-8')
    roundKeys = expandKey(key)
    index = 0
    result2 = [[[0 for k in range(4)] for j in range(4)] for i in range(11)]
    for counter in range(11):
        for i in range(4):
            for j in range(4):
                result2[counter][i][j] = "0x{:02x}".format(roundKeys[counter][j][i])
                index += 1

    file = "file.txt"

    file_Encrypt(file, result2)

    #sonuc = encryp_CBC(cbcPlainText,result2)
    #sonuc = decryption_CBC(sonuc, result2)
    """for i in range(4):
        for j in range(4):
            print(hex(sonuc[i][j]), end=" ")
        print("")"""
    #print("\nOFB ile Deşifrelenmiş metin\n")
    #printHexMatrix(sonuc)
    #decryption_CBC(sonuc,result2)
    #print(cbcPlainText)
   # sonuc = encrypt_OFB(cbcPlainText,result2)

    #printHexMatrix(sonuc)
    """sonuc = decryption_OFB(sonuc, result2)
    for i in range(len(sonuc)):
        if i % 16 == 0 and i > 0:
            print("\n")
        print(sonuc[i], end=" ")"""
    #printHexMatrix(sonuc)
    #decryption_OFB(sonuc,result2)

    #sonuc = encrypt(plaintextMatrixHex,result2,10)




if __name__ == '__main__':
    main()