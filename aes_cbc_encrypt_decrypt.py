#!/usr/bin/env python3


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180524'
__version__ = '0.01'
__description__ = """Performs AES CBC encryption or decryption on a supplied set of data."""


import argparse
import base64
import urllib.parse
import os
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Util.strxor import strxor
except ImportError as e:
    print("[-] Import Error. Try pip install pycryptodome")
    exit()


def url_encode(input_string):
    """Returns a URL encoded byte-string."""
    if type(input_string) == bytes:
        input_string = input_string.decode()
    if '%' not in input_string:
        return input_string.encode()
    return urllib.parse.quote_plus(input_string).encode()


def hex_encode(input_bytes):
    """Returns a hex encoded byte string."""
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode()
    return input_bytes.hex().encode()


def base64_encode(input_bytes):
    """Performs Base64 encoding."""
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode()
    return base64.b64encode(input_bytes)


def url_decode(input_string):
    """Returns a URL decoded byte-string."""
    if type(input_string) == bytes:
        input_string = input_string.decode()
    if '%' not in input_string:
        return input_string.encode()
    return urllib.parse.unquote(input_string).encode()


def hex_decode(input_string):
    """Returns a hex decoded byte string."""
    if type(input_string) == bytes:
        input_string = input_string.decode()
    return bytes.fromhex(input_string)


def base64_decode(input_bytes):
    """Performs Base64 decoding."""
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode()
    return base64.b64decode(input_bytes)


def encrypt_aes_ecb(data, key):
    """Returns data encrypted with AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)

    # Only pad the data if it isn't the size of the block
    if not len(data) % block_size == 0:
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
    else:
        ciphertext = cipher.encrypt(data)
    return ciphertext


def decrypt_aes_ecb(data, key):
    """Returns data decrypted with AES in ECB mode."""
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(data)
    try:
        return unpad(plaintext, AES.block_size)
    except ValueError:
        return plaintext


def encrypt_aes_cbc(data, key, iv):
    """Returns AES encrypted ciphertext in CBC mode."""
    # Sets the initial IV. During the encryption (in the for
    # loop), prev will be reset to previous ciphertext block.
    prev = iv
    ciphertext = b''

    # Divides the plaintext into block size-sized chunks
    plaintext_blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

    # Iterate over each block
    for plaintext_block in plaintext_blocks:

        # XORs block with the previous ciphertext block, or
        # with the IV if first block. 
        xor_data = strxor(plaintext_block, prev)

        # Encrypts the block and adds it to the ciphertext 
        # byte string
        ciphertext_block = encrypt_aes_ecb(xor_data, key)
        ciphertext += ciphertext_block
        prev = ciphertext_block 
    return ciphertext


def decrypt_aes_cbc(data, key, iv):
    """Returns plaintext from an AES encrypted ciphertext
    in CBC mode.
    """
    # Sets the initial IV. During the decryption (in the for
    # loop), prev will be reset to previous ciphertext block.
    prev = iv
    plaintext = b''

    # Divides the ciphertext into block size-sized chunks
    ciphertext_blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

    # Iterate over each block
    for ciphertext_block in ciphertext_blocks:

        # Decrypts the block. This block still needs to be XOR'd
        # against the previous block (or IV if first block) to 
        # recover the plaintext.
        decrypted_block = decrypt_aes_ecb(ciphertext_block, key)
        
        # XOR's the decrypted block with the previous block, or 
        # IV if the first block. This produces the plaintext
        plaintext += strxor(decrypted_block, prev)
        prev = ciphertext_block 
    return plaintext


def main():
    # This is an IV set to all zeroes...this is not secure.
    iv = bytes([0] * block_size)
    data = input_data
    if type(data) == str:
        data = data.encode()
    if args.url_decode:
        data = url_decode(data)
    if args.base64_decode:
        data = base64_decode(data)
    if args.hex_decode:
        data = hex_decode(data)
    if args.mode == 'encrypt':
        output = encrypt_aes_cbc(data, key, iv)
    if args.mode == 'decrypt':
        output = decrypt_aes_cbc(data, key, iv)
    if args.hex_encode:
        output = hex_encode(output)
    if args.base64_encode:
        output = base64_encode(output)
    if args.url_encode:
        output = url_encode(output)
    print(output)
    if args.outfile:
        with open(args.outfile, 'wb') as fh:
            fh.write(output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode",
                        choices=["encrypt", "decrypt"],
                        help="Specify whether to encrypt or decrypt")
    parser.add_argument("-k", "--key",
                        help="Specify the key to encrypt/decrypt with")
    parser.add_argument("-bs", "--block_size",
                        nargs="?",
                        type=int,
                        default=16,
                        help="Specify the block size")
    parser.add_argument("-d", "--data",
                        help="Specify the data as a string")
    parser.add_argument("-f", "--file",
                        help="Specify a file containing the data")
    parser.add_argument("-ue", "--url_encode",
                        help="Encode the output with URL encoding", 
                        action="store_true")
    parser.add_argument("-be", "--base64_encode",
                        help="Encode the output using Base64", 
                        action="store_true")
    parser.add_argument("-xe", "--hex_encode",
                        help="Encode the output as hex",
                        action="store_true")
    parser.add_argument("-ud", "--url_decode",
                        help="Decode the input with URL encoding", 
                        action="store_true")
    parser.add_argument("-bd", "--base64_decode",
                        help="Decode the input using Base64", 
                        action="store_true")
    parser.add_argument("-xd", "--hex_decode",
                        help="Decode the input as hex",
                        action="store_true")
    parser.add_argument("-o", "--outfile",
                        help="Specify the name of the output file")
    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        print("\n[-] Please specify to either encrypt or decrypt(-m decrypt).")
        exit()
    if not args.key:
        parser.print_help()
        print("\n[-] Please specify a key to encrypt/decrypt the data (-k mySecureKey12345).")
        exit()
    key = args.key.encode()
    if len(key) % 16 != 0:
        print("\n[-] Invalid key length. Please ensure the key is either 16 or 32 characters long.")
        exit()
    if not args.file and not args.data:
        parser.print_help()
        print("\n[-] Please specify data to encrypt/decrypt (-d data_to_cipher or -d /path/to/data/file).")
        exit()
    if args.data and args.file:
        parser.print_help()
        print('\n[-] Please specify either -d or -f, not both.\n')
        exit()
    if args.data:
        input_data = args.data
    if args.file:
        if not os.path.exists(args.file):
            print("\n[-] The file cannot be found or you do not have permission to open the file. Please check the path and try again\n")
            exit()
        else:
            with open(args.file, 'rb') as fh:
                input_data = fh.read()
    block_size = args.block_size
    main()