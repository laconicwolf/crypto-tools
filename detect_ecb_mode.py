#!/usr/bin/env python3


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180524'
__version__ = '0.01'
__description__ = """Attempts to detect ECB mode in ciphertext"""


import argparse
import base64
import urllib.parse
import os


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


def count_repetitions(ciphertext, block_size, line_number):
    """Breaks the ciphertext into block_size-sized chunks and 
    counts the number of repetitions. Returns the ciphertext
    and repetitions as a dictionary.
    """
    chunks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    number_of_repetitions = len(chunks) - len(set(chunks))
    result = {
        'ciphertext': ciphertext,
        'repetitions': number_of_repetitions,
        'line number': line_number
    }
    return result


def main():
    line_number = 1
    if args.line_by_line:
        data = input_data
    else:
        data = [input_data]
    repetitions = []
    for item in data:
        if type(item) == str:
            item = item.encode()
        if args.url_decode:
            item = decode_url_encoding(item)
        if args.b64_decode:
            item = base64.b64decode(item)
        if args.hex_decode:
            if b'\n' in item:
                item = item.replace(b'\n', b'')
            item = bytes.fromhex(item.decode())
        repetitions.append(count_repetitions(item, block_size, line_number))
        line_number += 1

    # Sorts the list of dictionaries by the repetitions key and returns the dict 
    # with the largest value
    most_repetitions = sorted(repetitions, key=lambda x: x['repetitions'], reverse=True)[0]
    print("Ciphertext: {}...".format(most_repetitions['ciphertext'][:10]))
    print("Repeating Blocks: {}".format(most_repetitions['repetitions']))
    if args.line_by_line:
        print("Line number: {}".format(most_repetitions['line number']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose",
                        help="Increase output verbosity", 
                        action="store_true")
    parser.add_argument("-d", "--data",
                        help="Specify the data as a string")
    parser.add_argument("-bs", "--block_size",
                        nargs="?",
                        type=int,
                        default=16,
                        help="Specify the block size")
    parser.add_argument("-f", "--file",
                        help="Specify a file containing the data")
    parser.add_argument("-u", "--url_decode",
                        help="Decode the URL encoded characters", 
                        action="store_true")
    parser.add_argument("-b", "--b64_decode",
                        help="Decode the b64 encoded data", 
                        action="store_true")
    parser.add_argument("-l", "--line_by_line",
                        help="Checks entropy of data in a file line by line",
                        action="store_true")
    parser.add_argument("-x", "--hex_decode",
                        help="Decode the hex encoded data",
                        action="store_true")
    args = parser.parse_args()

    if not args.data and not args.file:
        parser.print_help()
        print('\n[-] Please specify the encrypted data (-d data) or specify a file containing the data (-f /path/to/data).\n')
        exit()
    if args.data and args.file:
        parser.print_help()
        print('\n[-] Please specify either -d or -f, not both.\n')
        exit()
    if args.data:
        if args.line_by_line:
            print('\n[-] -l option only available with -f.\n')
        input_data = args.data
    if args.file:
        if not os.path.exists(args.file):
            print("\n[-] The file cannot be found or you do not have permission to open the file. Please check the path and try again\n")
            exit()
        else:
            if args.line_by_line:
                input_data = open(args.file, 'rb').read().splitlines()
            else:
                input_data = open(args.file, 'rb').read()
    block_size = args.block_size
    main()
