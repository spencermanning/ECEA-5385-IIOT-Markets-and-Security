# Set 1

import base64
from itertools import cycle # for challenge 5
from Crypto.Cipher import AES # for challenge 7

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
        decoded_b64 = base64.b64decode(b64_data)

        # 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, 
        # and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
        norm_ham_list = []
        for KEYSIZE in range (2, 40):
            bytes1 = decoded_b64[:KEYSIZE]
            bytes2 = decoded_b64[KEYSIZE:2*KEYSIZE]

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
        groups = [b64_data[i:i+smallest_keysize] for i in range(0, len(b64_data), smallest_keysize)]

        #6. Now transpose the blocks: make a block that is the first byte of every block, 
        # and a block that is the second byte of every block, and so on.
        # FIXME: Make automatic for different keysizes
        trans_groups = ["", ""]
        group1 = [grp[0] for grp in groups]
        group2 = [grp[1] if len(grp) > smallest_keysize-1 else '' for grp in groups]

        #7. Solve each block as if it was single-character XOR. You already have code to do this.
        group1_comb = ''.join(group1)
        group2_comb = ''.join(group2)
        # group1_comb = group1_comb.replace("\n", "")
        # group2_comb = group2_comb.replace("\n", "")
        group1_comb += '=' * ((4 - len(group1_comb) % 4) % 4) # pad with equal signs to be a multiple of 4 bytes long
        group2_comb += '=' * ((4 - len(group2_comb) % 4) % 4) # pad with equal signs to be a multiple of 4 bytes long
        # test1 = "HITsA9E4GlHkD4AsTsFUA4SQV0QNTVgHBNUHATjMgJgRxMRHwFUZQJGm1AxGDoQ0UQXAEoR8ShTUFkRYCpB8WhaID0QIlawdnEgJgRl60ADAhJkFAdVEgSQLQMAwXNFYCdCdFZeMCsB9B8ThSdBcRhEAyUHLRJgOlAjpRJgUAL0CFBhVQHhPG5MkUoCQBlTIUgEYS8E8ApRsSQTQEMwWXMkPgD1MUAwJQOwVBPhFiLRBgKV4T9BERMDAFoHwQ5LFI4SRQIB9K4C8GFjExMhcgHxUhJQZCFwDVHU4AKRJl3wmHdEAANT5FQC5HYG9dBAsH4VUD5TgRkm6UTgA1GlKxTUsAAwXwSQLQb09iWgcAcStTsAYCVCIGgRgaUScAkR8AkDUF1gRxJlJwJQAURAWRKgSAOBLlw1ixOEUYRC8UYCICAE8RxRBHYTQClBARpU0DhXzFH1bkNDAUbRFwXRPlY02wuxakUAAZYVZCQSMVcQwU1BsAAAACgRQERGkAdBqRJ0DQFhBlMEHUPxP0zwrkdFaEHQNU9SBW4G9DhT0A4TQC0T4CBesHEA1eZRFiAAOUCFXBfBOAdUxVxm9lRgBgPQzD4GoFoUFTsB0TERoSRBpFsCITNPpKMhPUGQPxRG7QP1b09kiAX0dgAwNw1hNAsVgVYKgTNT0AADQCpXBPAH1e5YYA5QFjHAAxSwORB02Qiwb0VkUBJw0RDkrNoAFVUB4RERQFAQQH0CVAsK5LdZhEpQLRTReRcBb09kjQd1RgFRJShVDhBQSWdBAS9TsAUQlb0BoAECYNVKcCsGdUIhJAdRHBDk3krAdynwOkEy8RUSOESDXRADdA0EAHYBYC0DVZFO1JYBdHwA9GMwTSBBPU40mhPgdEAG/j6SMwNASTfDXGJWESASRBsGNTkHYNNJITVHYAQBcLwBHxPU403hakTRAgCk1QEwBjdCPiBRTTREIBcRUF0BMTFNoIABkVIQAB8dwCklc000lgAwNxAgGwxRfEDRbnamxBUVfDlGERIFwHEHcMVKsSdHMA0CkdIGxakE2QjAOFbxJEJxtBKROBbjaSdwHjEQaBsEMUkCEBdLUJAAFG9VYGMMcToDNe4Q7RJUUQBANwtQFE3TSDJycWtwNVHUTFtGwCEBlesBcAZVYWdYANcAwQYUQXAxLAcRUwOwmgDUrAXjd2ckThYUAEc3IGMQES8M9NICNHZAoH1XYDsAkBkFAVR0awOUdg8VBAEASjUTbktRdVchDDFwJA8CJN4CIBhEAAoCdXwGkCMBAWYUARo0TgZw7hNAFAXjaSSASlNFOULHMEE0AB9epLdTARgU4EMMQQla0BcXAFgA4BIAa00DMQPE7DbmGALBcS3BBTKhOUTgUMQYoGsBdA0SpNQToBgUkGoHkC5HVC8g0BJQOkGDfDTUtzJFLxbHJxARURM1HYYT5MReESAOUDUQkUQXBKYQISVGwGtRNwVEB3JCCQGxIEKwdSX0jgAwIRXwKBdGsTxSoMlCZFwUQVMU0RMGAZwUYCdBBwdzaSWQIlcULxCDX0jwBwBlBhIhMEgR5RMOwBQTQHkUUFlbkHVBAF0RYCpUFSayTkHhRQXBUzFgIkDROxqRJQNUKTJDUJwA0QUFAU4U0DNGpC9eYHJR4G4CSTSxJwIFdgTjckOUDxURCQFgPBNRKSELUAlEgCAUEU8CsShHYUIRUAoV0WQySgOBI0X0UnvgQgbBAVEhGQJUEgPRELUBgQIHsG0AARQBkFAUEAxYQG4AxQZxJwIFdgTjI0GEUBNRPFJgUAAAKAFjeDBFwBAT4CkEMCVBYFUCtEEVwWhV5G8BcS+wKSNxJBaAAUTxJ0MRRAPRQAAQBFRIwQAGgRYB5TIAwSIAcE8TEY0D4ThkDkc3FQE0bVqFB1dgUAQgWRQwRW"
        # test = base64.b64decode(test1)

        # --------------------------
        # FIXME: WHY IS group1_comb length wrong for the b64 decode? Should I restructure how I break the code apart above?
        group1_decoded = base64.b64decode(group1_comb)
        group2_decoded = base64.b64decode(group2_comb)
        group1_hex = group1_decoded.hex()
        group2_hex = group2_decoded.hex()
        best_score, best_key, best_decrypted_text = s1_ch3(group1_hex)
        best_score, best_key, best_decrypted_text = s1_ch3(group2_hex)

        # best_score, best_key, best_decrypted_text = s1_ch3(test2)
        print(f"Key: {best_key}. Text: {best_decrypted_text}. Score: {round(best_score), 2}")

    print("Done")

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
    # s1_ch5()
    # s1_ch6()
    s1_ch7()
    # s1_ch8()

    print("\n------------------ End: ------------------")


