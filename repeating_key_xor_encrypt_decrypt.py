#!/usr/bin/env python3


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180523'
__version__ = '0.01'
__description__ = """Performs repeating-key XOR on a provided set of data."""


import argparse
import base64
import urllib.parse
import os


def url_encode(input_string):
    """Returns a URL encoded byte-string"""
    if type(input_string) == bytes:
        input_string = input_string.decode()
    if '%' not in input_string:
        return input_string.encode()
    return urllib.parse.quote_plus(input_string).encode()


def hex_encode(input_bytes):
    """Returns a hex encoded byte string"""
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode()
    return input_bytes.hex().encode()


def base64_encode(input_bytes):
    """Performs Base64 encoding"""
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode()
    return base64.b64encode(input_bytes)


def url_decode(input_string):
    """Returns a URL decoded byte-string"""
    if type(input_string) == bytes:
        input_string = input_string.decode()
    if '%' not in input_string:
        return input_string.encode()
    return urllib.parse.unquote(input_string).encode()


def hex_decode(input_string):
    """Returns a hex decoded byte string"""
    if type(input_string) == bytes:
        input_string = input_string.decode()
    return bytes.fromhex(input_string)


def base64_decode(input_bytes):
    """Performs Base64 decoding"""
    if type(input_bytes) == str:
        input_bytes = input_bytes.encode()
    return base64.b64decode(input_bytes)


def repeating_key_xor(message_bytes, key):
    """Returns message XOR'd with a key. If the message, is longer
    than the key, the key will repeat.
    """
    output_bytes = b''
    index = 0
    for byte in message_bytes:
        output_bytes += bytes([byte ^ key[index]])
        if (index + 1) == len(key):
            index = 0
        else:
            index += 1
    return output_bytes


def main():
    data = input_data
    if type(data) == str:
        data = data.encode()
    if args.url_decode:
        data = url_decode(data)
    if args.base64_decode:
        data = base64_decode(data)
    if args.hex_decode:
        data = hex_decode(data)
    cipher = repeating_key_xor(data, key)
    if args.hex_encode:
        cipher = hex_encode(cipher)
    if args.base64_encode:
        cipher = base64_encode(cipher)
    if args.url_encode:
        cipher = url_encode(cipher)
    print(cipher)
    if args.outfile:
        with open(args.outfile, 'wb') as fh:
            fh.write(cipher)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key",
                        help="Specify the key to encrypt/decrypt with")
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
                        help="Encode the output as hex.",
                        action="store_true")
    parser.add_argument("-ud", "--url_decode",
                        help="Decode the input with URL encoding", 
                        action="store_true")
    parser.add_argument("-bd", "--base64_decode",
                        help="Decode the input using Base64", 
                        action="store_true")
    parser.add_argument("-xd", "--hex_decode",
                        help="Decode the input as hex.",
                        action="store_true")
    parser.add_argument("-o", "--outfile",
                        help="Specify the name of the output file")
    args = parser.parse_args()

    if not args.key:
        parser.print_help()
        print("\n[-] Please specify a key to encrypt/decrypt the data (-k mySecureKey123).")
        exit()
    key = args.key.encode()
    if not args.file and not args.data:
        parser.print_help()
        print("\n[-] Please specify a data to encrypt/decrypt (-d data_to_cipher or -d /path/to/data/file).")
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
    if len(input_data) < len(key):
        print('\n[-] The data cannot be shorter than the key. Choose a shorter key.')
        exit()
    main()