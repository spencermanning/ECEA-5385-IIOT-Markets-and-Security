import base64
from Crypto.Util.Padding import pad, unpad  # for ch1
def s2_ch9():
    print(f"s2_ch9")
    msg = b"YELLOW SUBMARINE"
    padded_msg = pad(msg, 20)
    print(padded_msg)


def s2_ch10():
    print(f"s2_ch10")

def s2_c3():
    print(f"s2_ch11")

def s2_ch12():
    print(f"s2_ch12")

def s2_ch13():
    print(f"s2_ch13")

def s2_ch14():
    print(f"s2_ch14")

def s2_ch15():
    print(f"s2_ch15")

def s2_ch16():
    print(f"s2_ch16")

if __name__ == "__main__":
    print("\n------------------ Start: ------------------")

    s2_ch9()
    # s2_ch10()
    # s2_ch11()
    # s2_ch12()
    # s2_ch13()
    # s2_ch14()
    # s2_ch15()
    # s2_ch16()

    print("\n------------------ End: ------------------")