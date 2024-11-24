# Set 1 Challenge 1

import base64

hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
byte_data = bytes.fromhex(hex)

b64 = base64.b64encode(byte_data).decode()

print("\n------------------ Start: ------------------")
print(f"b64: {b64}")
