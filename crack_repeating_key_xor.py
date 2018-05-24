#!/usr/bin/env python3


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180523'
__version__ = '0.01'
__description__ = """Decrypts repeating-key XOR by recovering the key."""


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


def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language.
    """

    # From https://en.wikipedia.org/wiki/Letter_frequency
    # with the exception of ' ', which I estimated.
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])


def single_char_xor(input_bytes, char_value):
    """Returns the result of each byte being XOR'd with a single value."""
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes


def bruteforce_single_char_xor(ciphertext):
    """Performs a singlechar xor for each possible value(0,255), and
    assigns a score based on character frequency. Returns the result
    with the highest score.
    """
    potential_messages = []
    for key_value in range(256):
        message = single_char_xor(ciphertext, key_value)
        score = get_english_score(message)
        data = {
            'message': message,
            'score': score,
            'key': key_value
            }
        potential_messages.append(data)
    return sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0]


def break_repeating_key_xor(ciphertext):
    """Attempts to break repeating-key XOR encryption."""
    average_distances = []

    # Take the keysize from suggested range 
    for keysize in range(2,41):

        # Initialize list to store Hamming distances for this keysize 
        distances = []

        # Break the ciphertext into chunks the length of the keysize
        chunks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
        
        while True:
            try:
                # Take the two chunks at the beginning of the list and 
                # get the Hamming distance 
                chunk_1 = chunks[0]
                chunk_2 = chunks[1]
                distance = calculate_hamming_distance(chunk_1, chunk_2)

                # Normalize this result by dividing by KEYSIZE
                distances.append(distance/keysize)

                # Remove these chunks so when the loop starts over, the
                # Hamming distance for the next two chunks can be calculated
                del chunks[0]
                del chunks[1]

            # When an exception occurs (indicating all chunks have 
            # been processed) break out of the loop.
            except Exception as e:
                break
        result = {
            'key': keysize,
            'avg distance': sum(distances) / len(distances)
            }
        average_distances.append(result)
        
    # Taking the five shortest normalized distances
    possible_key_lengths = sorted(average_distances, key=lambda x: x['avg distance'])[:5]
    
    possible_plaintext = []
    # Iterating through each of out five results with the shortest
    # normalized differences
    for res in possible_key_lengths:
        # Will populate with a single character as each transposed 
        # block has been single-byte XOR brute forced
        key = b''
        #possible_key_length = possible_key_lengths['key']
        for i in range(res['key']):

            # Creates an block made up of each nth byte, where n
            # is the keysize
            block = b''
            for j in range(i, len(ciphertext), res['key']):
                block += bytes([ciphertext[j]])
            key += bytes([bruteforce_single_char_xor(block)['key']]) 
        possible_plaintext.append((repeating_key_xor(ciphertext, key), key)) 
    return max(possible_plaintext, key=lambda x: get_english_score(x[0]))


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


def calculate_hamming_distance(input_bytes_1, input_bytes_2):
    """Finds and returns the Hamming distance (number of differing 
    bits) between two byte-strings
    """
    hamming_distance = 0
    for b1, b2 in zip(input_bytes_1, input_bytes_2):
        difference = b1 ^ b2

        # Count the number of differences ('1's) and add to the hamming distance
        hamming_distance += sum([1 for bit in bin(difference) if bit == '1'])
    return hamming_distance


def main():
    ciphertext = input_data
    if type(ciphertext) == str:
        ciphertext = ciphertext.encode()
    if args.url_decode:
        ciphertext = url_decode(ciphertext)
    if args.base64_decode:
        ciphertext = base64_decode(ciphertext)
    if args.hex_decode:
        ciphertext = hex_decode(ciphertext)
    result, key = break_repeating_key_xor(ciphertext)
    print("Key: {}\nMessage: {}".format(key, result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--data",
                        help="Specify the data as a string")
    parser.add_argument("-f", "--file",
                        help="Specify a file containing the ciphertext")
    parser.add_argument("-u", "--url_decode",
                        help="Decode the input with URL encoding", 
                        action="store_true")
    parser.add_argument("-b", "--base64_decode",
                        help="Decode the input using Base64", 
                        action="store_true")
    parser.add_argument("-x", "--hex_decode",
                        help="Decode the input as hex",
                        action="store_true")
    parser.add_argument("-o", "--outfile",
                        help="Specify the name of the output file")
    args = parser.parse_args()
    if not args.file and not args.data:
        parser.print_help()
        print("\n[-] Please specify a data to decrypt (-d data_to_decrypt or -d /path/to/data/file).")
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
    main()