# Set 1 and 2

import base64
from itertools import cycle # for challenge 5
from Crypto.Cipher import AES # for challenge 7
from Crypto.Util.Padding import pad, unpad  # for challenge 9

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
def ham(str1, str2):
    str1 = ''.join(format(byte, '08b') for byte in str1.encode('utf-8'))
    str2 = ''.join(format(byte, '08b') for byte in str2.encode('utf-8'))

    ham = 0
    for b1, b2 in zip(str1, str2):
        if b1 != b2:
            ham += 1
    # print(ham)
    return ham

def s1_ch6():
    print(f"s1_ch6")
    # ham("this is a test", "wokka wokka!!!")

    with open("ch6_text.txt", "r") as orig_file:
        b64_data = orig_file.read()
        b64_decoded = base64.b64decode(b64_data)

        # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, 
        # and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
        norm_ham_list = []
        for KEYSIZE in range (2, 40):
            bytes1 = b64_decoded[:KEYSIZE]
            bytes2 = b64_decoded[KEYSIZE:2*KEYSIZE]

            ham_out = ham(str(bytes1), str(bytes2))
            norm_ham = ham_out/KEYSIZE

            norm_ham_list.append(norm_ham)

        # 4. The KEYSIZE with the smallest normalized edit distance is probably the key. 
        # You could proceed perhaps with the smallest 2-3 KEYSIZE values. 
        # Or take 4 KEYSIZE blocks instead of 2 and average the distances.
        smallest_keysize_idx = norm_ham_list.index(min(norm_ham_list))
        smallest_keysize = smallest_keysize_idx+2 # we started testing with 2 KEYSIZE
        print(f"Smallest keysize: {smallest_keysize}")

        # 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
        groups = [b64_decoded[i:i+smallest_keysize] for i in range(0, len(b64_decoded), smallest_keysize)]

        #6. Now transpose the blocks: make a block that is the first byte of every block, 
        # and a block that is the second byte of every block, and so on.
        # FIXME: Make automatic for different keysizes
        trans_groups = ["", ""]
        group1 = [grp[0] for grp in groups]
        group2 = [grp[1] if len(grp) > smallest_keysize-1 else '' for grp in groups]

        #7. Solve each block as if it was single-character XOR. You already have code to do this.
        group1_hex = ''.join(f"{x:02x}" for x in group1)
        group2_hex = ''.join(f"{x:02x}" for x in group2)
        best_score, best_key, best_decrypted_text = s1_ch3(group1_hex)
        best_score, best_key, best_decrypted_text = s1_ch3(group2_hex)

        # best_score, best_key, best_decrypted_text = s1_ch3(test2)
        # 8. For each block, the single-byte XOR key that produces the best looking histogram 
        # is the repeating-key XOR key byte for that block. Put them together and you have the key.
        print(f"Key: {best_key}. Text: {best_decrypted_text}. Score: {round(best_score), 2}")

    print("Done")

# --------- s1_ch7 ---------
def ecb_decrypt(ciphertext, key):
    # Make the AES cipher from the given key
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def s1_ch7():
    print(f"s1_ch7")
    key = b"YELLOW SUBMARINE"
    with open("ch7_text.txt", "r") as orig_file:
        b64_coded_data = orig_file.read()
        ciphertext = base64.b64decode(b64_coded_data)

        plaintext = ecb_decrypt(ciphertext, key)

        print(plaintext.decode("utf-8", errors="ignore"))

# --------- s1_ch8 ---------
def s1_ch8():
    print(f"s1_ch8")
    with open("ch8_text.txt", "r") as file:
        ciphertexts = file.readlines()

        ecb_suspects = []

        for idx, line in enumerate(ciphertexts):
            line = line.strip()
            cipher_line_bytes = bytes.fromhex(line)
            chunks = [cipher_line_bytes[i:i+16] for i in range(0, len(cipher_line_bytes), 16)]
            # set() removes duplicates. So if a line had any duplicates, the comparison with len(chunks) woud be different.
            num_repeats = len(chunks) - len(set(chunks))

            if num_repeats > 0:
                ecb_suspects.append((idx, num_repeats, line))

        ecb_suspects.sort(key=lambda x:x[1], reverse=True)

        # There is only one line that has been encrypted with ECB. Index 132.
        print(ecb_suspects)

# --------- s1_ch9 ---------
def pad_msg(byte_text):
    return pad(byte_text, 20)

def s2_ch9(byte_text):
    print(f"s2_ch9")
    print(pad_msg(byte_text))

# --------- s1_ch10 ---------
def ecb_encrypt(plaintext, key):
    # Make the AES cipher from the given key
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def xor_strings(str1, str2):
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes.fromhex(str1), bytes.fromhex(str2)))

# CBC encrypt with ECB
def cbc_encrypt(plaintext, IV, key):
    ciphertext = ""
    for block in plaintext:
        if block == 1:
            xor_str = IV
        else:
            xor_str = next_block

        # combine with next plain-text block
        xor_out = xor_strings(block, xor_str)

        ciphertext.append(ecb_encrypt(xor_out))
        next_block = ciphertext
    return ciphertext

def cbc_decrypt(ciphertext, IV, key):
    print("Start cbc_decrypt()")

    print(ecb_decrypt(ciphertext, "YELLOW SUBMARINE"))

def s2_ch10():
    print(f"s2_ch10")
    IV = "\x00" * 16 # FIXME: is 16 bytes correct?
    key = b"YELLOW SUBMARINE"

    # TODO: Implement CBC mode by hand by taking the ECB function you wrote earlier, 
    # making it encrypt instead of decrypt 
    # (verify this by decrypting whatever you encrypt to test), 
    # and using your XOR function from the previous exercise to combine them.

    # encrypt a test string
    testplain = "hello"
    ciphertext = cbc_encrypt(testplain, IV, key)

    # decrypt the test string
    cbc_decrypt(ciphertext, IV, key)

    # Test decryption with my decryption function to make sure it works properly.
    with open("ch10_text.txt", "r") as file:
        ciphertext = file.read() # FIXME: should it be realines()?
        cbc_decrypt(ciphertext)

# --------- s1_ch11 ---------
def s2_c11():
    print(f"s2_ch11")

# --------- s1_ch12 ---------
def s2_ch12():
    print(f"s2_ch12")

# --------- s1_ch13 ---------
def s2_ch13():
    print(f"s2_ch13")

# --------- s1_ch14 ---------
def s2_ch14():
    print(f"s2_ch14")

# --------- s1_ch15 ---------
def s2_ch15():
    print(f"s2_ch15")

# --------- s1_ch16 ---------
def s2_ch16():
    print(f"s2_ch16")


if __name__ == "__main__":
    print("\n------------------ Start: ------------------")

    # s1_ch1
    # hexTobase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

    # s1_ch2("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
    # s1_ch3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    # s1_ch4()
    # s1_ch5()
    # s1_ch6()
    # s1_ch7()
    # s1_ch8()
    # s2_ch9(b"YELLOW SUBMARINE")
    s2_ch10()
    # s2_ch11()
    # s2_ch12()
    # s2_ch13()
    # s2_ch14()
    # s2_ch15()
    # s2_ch16()

    print("\n------------------ End: ------------------")


