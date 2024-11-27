import string

# Frequency of letters in English, sorted from most to least frequent
ENGLISH_FREQ = {
    'e': 12.702, 't': 9.056, 'a': 8.167, 'o': 7.507, 'i': 6.966, 'n': 6.749, 
    's': 6.327, 'r': 6.017, 'h': 5.749, 'd': 4.253, 'l': 4.025, 'u': 3.636, 
    'c': 3.398, 'm': 3.340, 'f': 3.031, 'y': 2.758, 'p': 2.021, 'b': 1.492, 
    'v': 0.978, 'k': 0.772, 'j': 0.153, 'x': 0.150, 'q': 0.095, 'z': 0.074
}

# Function to calculate the English score of a given text
def score_text(text):
    text = text.lower()
    score = 0
    for char in text:
        if char in ENGLISH_FREQ:
            score += ENGLISH_FREQ[char]
    return score

# Function to decrypt using XOR with every possible byte key
def decrypt_xor(hex_string):
    # Convert hex string to bytes
    byte_string = bytes.fromhex(hex_string)
    
    best_score = -1
    best_decrypted_text = ''
    best_key = None
    
    # Try every possible single-byte key (0x00 to 0xFF)
    for key in range(256):
        decrypted = ''.join(chr(b ^ key) for b in byte_string)
        
        # Score the decrypted text
        current_score = score_text(decrypted)
        
        # If this score is better, update best result
        if current_score > best_score:
            best_score = current_score
            best_decrypted_text = decrypted
            best_key = key
    
    return best_key, best_decrypted_text

# The given hex-encoded string
hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

# Decrypt the message and find the best key and plaintext
key, decrypted_message = decrypt_xor(hex_string)

print(f"Key: {key}")
print(f"Decrypted Message: {decrypted_message}")
