# Set 1

import base64
from itertools import cycle # for challenge 5

# --------- s1_ch1 ---------
def hexTobase64(hex):
    byte_data = bytes.fromhex(hex)
    b64 = base64.b64encode(byte_data).decode()
    print(f"b64: {b64}")

# --------- s1_ch2 ---------
def s1_ch2(buf1, buf2):
    print(f"s1_ch2")

    bufout = bytes(b1 ^ b2 for b1, b2 in zip(bytes.fromhex(buf1), bytes.fromhex(buf2)))
    print(f"Bufout: {bufout}")
    print(f"Encoded bufout: {bufout.hex()}")
    return bufout

# --------- s1_ch3 ---------+
# FIXME: DOESN'T WORK. GETS 82 WHEN THE ANSEWR IS 88.
# English letter frequency for scoring
ENGLISH_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
    'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
    'l': 4.03, 'u': 2.76, 'c': 2.23, 'm': 2.02, 'f': 1.97,
    'p': 1.93, 'g': 1.50, 'y': 1.49, 'b': 1.38, 'v': 1.06,
    'k': 0.69, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
}

def score_text(text):
    text = text.lower()
    score = 0
    for char in text:
        if char in ENGLISH_FREQ:
            score += ENGLISH_FREQ[char]
    return score

def s1_ch3(hex_string):
    # print(f"s1_ch3")

    unencoded = bytes.fromhex(hex_string)

    best_score = -1
    best_decrypted_text = ''
    best_key = None

    for key in range(256):
        decrypted = ''.join(chr(b ^ key) for b in unencoded)

        current_score = score_text(decrypted)
        # decrypted = decrypted.lower()
        # score = 0
        # for char in decrypted:
        #     if char in english_freq:
        #         score += english_freq[char]

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_decrypted_text = decrypted

    return best_score, best_key, best_decrypted_text
    # print(f"Key: {best_key}. Text: {best_decrypted_text}. Score: {round(best_score), 2}")

# --------- s1_ch4 ---------
def s1_ch4():
    print(f"s1_ch4")

    with open("ch4_text.txt", "r") as file:
        for line in file:
            best_score, best_key, best_decrypted_text = s1_ch3(line)

            if best_decrypted_text[0:3] == "nOW":
                print(f"Line: {line}") # Answer: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
                print(f"Key: {best_key}. Text: {best_decrypted_text}. Score: {round(best_score), 2}")

# --------- s1_ch5 ---------
def s1_ch5():
    print(f"s1_ch5")

    stanza = '''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''

    # for key in "ICE".encode():
    #     for byte in stanza.encode():
    #         print(byte ^ key)

    comb = ''
    for key, byte in zip(cycle("ICE".encode()), stanza.encode()):
        comb += format(key ^ byte, '02x')

    # This should be two lines to be the full correct answer.
    # Answer: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    print(comb)

# --------- s1_ch6 ---------
def s1_ch6():
    print(f"s1_ch6")


# --------- s1_ch7 ---------
def s1_ch7():
    print(f"s1_ch7")


# --------- s1_ch8 ---------
def s1_ch8():
    print(f"s1_ch8")

if __name__ == "__main__":
    print("\n------------------ Start: ------------------")

    # s1_ch1
    # hexTobase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

    # s1_ch2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
    # s1_ch3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    # s1_ch4()
    s1_ch5()
    # s1_ch6()
    # s1_ch7()
    # s1_ch8()

    print("\n------------------ End: ------------------")


