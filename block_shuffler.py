#!/usr/bin/env python3


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180529'
__version__ = '0.01'
__description__ = """Generates data that has been shuffled into multiple 
block-sized chunks. Intended to be used on cookie values where the
encryption mode used is ECB. The goal is to replay the generated cookie
values and see if the application responds in an unexpected way.
"""


import argparse
import base64
import urllib.parse


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


def get_chunks(data, n):
    """Returns a list of n sized strings from a specified string."""
    return [data[i:i+n] for i in range(0, len(data), n)]


def rotate(data_list, n):
    """Rotates a list by n positions"""
    return data_list[n:] + data_list[:n]


def decode_data(data):
    """Returns data that will be decoded if specified by command 
    line arguments.
    """
    if type(data) == str:
        data = data.encode()
    if args.url_decode:
        data = url_decode(data)
    if args.base64_decode:
        data = base64_decode(data)
    if args.hex_decode:
        data = hex_decode(data)
    return data


def encode_data(data):
    """Returns data that will be encoded if specified by command 
    line arguments.
    """
    if type(data) == str:
        data = data.encode()
    if args.hex_encode:
        data = hex_encode(data)
    if args.base64_encode:
        data = base64_encode(data)
    if args.url_encode:
        data = url_encode(data)
    return data


def shuffle_blocks(data):
    """Returns a list of strings that are shuffled to the 
    length of several potential blocksizes.
    """
    shuffled_data = []
    potential_block_sizes = [8, 16, 24, 32]
    for block_size in potential_block_sizes:
        chunks = get_chunks(data, block_size)
        for i in range(len(chunks)):
            shuffled_data.append(b''.join(chunks))
            chunks = rotate(chunks, 1)
    return shuffled_data


def main():
    data = decode_data(input_data)
    shuffled_data = shuffle_blocks(data)
    shuffled_data = [encode_data(item).decode() for item in shuffled_data]
    for item in shuffled_data:
        print(item)
        if args.outfile:
            outfile.write(item + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--data",
                        help="Specify the data as a string")
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

    if not args.data:
        parser.print_help()
        print("\n[-] Please specify data to shuffle (-d data_to_shuffle).")
        exit()
    if args.outfile:
        outfile = open(args.outfile, 'w')
    input_data = args.data
    main()