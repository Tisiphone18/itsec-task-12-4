import binascii
import socket

# If you have done that, copy over a hexlified message + IV over to this script (replacing the zeros)
iv = binascii.unhexlify("507dac229ba1ce86991054cfa76c102f")
msg = binascii.unhexlify(
    "fa56b5c113b6c4c008e52aa62d8fdbc31c71c7d4b2017652fe22b35e0a0f270887794a12375e9ecfe1e8fd54027769140abaa5445c59b251a22fb2ad36be6896")


def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf


def check_padding(iv, blocks):
    """Checks if the padding is valid by sending the encrypted message to the padding oracle"""
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))

    start = read_until(s, b"Do you")
    s.send(binascii.hexlify(iv) + b"\n")
    s.send(binascii.hexlify(b''.join(blocks)) + b"\n")

    response = read_until(s, b"\n")
    return b"OK" in response


def xor_lists(a, b):
    """XORs two lists of bytes"""
    return [a[i] ^ b[i] for i in range(len(a))]


def xor_block_with_list(block, list):
    """XORs a block with a list of bytes"""
    return bytes([(block[i] ^ (list[i])) for i in range(len(block))])


def decrypt_char(iv, blocks, decrypted_values, i):
    """Decrypts a single byte"""
    blocks_copy = blocks.copy()
    iv_copy = iv

    # calculate padding for i
    padding = ([0x0] * (15 - i)) + ([i + 1] * (i + 1))

    # xor padding with the previous decrypted values
    decripted_values_with_padding = xor_lists(padding, decrypted_values)

    # test padding for the i-th byte in the block
    for n in range(0, 256):
        # exclude the case, where evil is 0x0 (trivially true)
        if n == i + 1:
            continue

        # value to be XORed with the block
        evil = xor_lists(decripted_values_with_padding, [0x0] * (15 - i) + [n] + [0x0] * i)

        # xor the block (or the iv) with the evil value
        if (len(blocks) > 1):
            blocks_copy[-2] = xor_block_with_list(blocks[-2], evil)
        else:
            iv_copy = xor_block_with_list(iv, evil)

        # check if the padding is valid
        if check_padding(iv_copy, blocks_copy):
            decrypted_values[15 - i] = n
            return n

    # if no valid padding found, it is the value we skipped before
    decrypted_values[15 - i] = i + 1
    return i + 1


def decypt_block(iv, blocks, decrypted):
    """Decrypts a single block"""
    decrypted_values = [0x0] * 16

    # decrypt each byte in the block
    for i in range(0, 16):
        n = decrypt_char(iv, blocks, decrypted_values, i)
        decrypted.append(n)
        print(str(bytes(decrypted[::-1]))[2:-1])


# The server allows you to process a single message with each connection.
# Connect multiple times to decrypt the (IV, msg) pair above byte by byte.
def main():
    decrypted = []

    # divide the message into blocks of 16 bytes
    blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)]

    # decrypt blocks
    for i in range(len(blocks)):
        decypt_block(iv, blocks, decrypted)
        # remove blocks after they are fully decripted
        blocks.pop()

    # print the decrypted message
    print(f"\nDecrypted message: {bytes(decrypted[::-1])}")

if __name__ == "__main__":
    main()

#flag_bytes = b'This is your flag: flag{15de674f8c8aea5991a8410da27521ff4760}\n\n\x01'
