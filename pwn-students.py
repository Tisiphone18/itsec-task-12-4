import binascii
import socket

iv = binascii.unhexlify("507dac229ba1ce86991054cfa76c102f")
msg = binascii.unhexlify("fa56b5c113b6c4c008e52aa62d8fdbc31c71c7d4b2017652fe22b35e0a0f270887794a12375e9ecfe1e8fd54027769140abaa5445c59b251a22fb2ad36be6896")


def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf

def char_entschluesseln(iv, blocks, decrypted_values, i):
    """Decrypts a single byte"""

    decripted_values_with_padding = [0x0] * 16
    for j in range(0, 16):
        if j < (15 - i):
            decripted_values_with_padding[j] = decrypted_values[j] ^ 0x00
        else:
            decripted_values_with_padding[j] = decrypted_values[j] ^ (i+1)


    # test padding for the i-th byte in the block
    for char in range(0, 256):
        # exclude the case, where angriffsvektor is 0x0 (trivially true)
        if char != i + 1:

            # value to be XORed with the block
            aux = [0x0] * (15 - i) + [char] + [0x0] * i
            angriffsvektor = [decripted_values_with_padding[i] ^ aux[i] for i in range(len(decripted_values_with_padding))]

            # xor the block (or the iv) with the angriffsvektor value

            blocks_permuted = blocks[:]
            iv_permuted = iv
            if (len(blocks) == 1):
                iv_permuted = bytes([(iv[i] ^ (angriffsvektor[i])) for i in range(len(iv))])
            else:
                blocks_permuted[-2] = bytes([(blocks[-2][i] ^ (angriffsvektor[i])) for i in range(len(blocks[-2]))])

            # padding stimmt ?

            s = socket.socket()
            s.connect(("itsec.sec.in.tum.de", 7023))

            start = read_until(s, b"Do you")
            s.send(binascii.hexlify(iv_permuted) + b"\n")
            s.send(binascii.hexlify(b''.join(blocks_permuted)) + b"\n")
            response = read_until(s, b"\n")
            if b"OK" in response:
                decrypted_values[15 - i] = char
                return char

    decrypted_values[15 - i] = i + 1
    return i + 1

def main():
    flag = []

    bloecke = []
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        bloecke.append(block)

    # decrypt blöcke
    for i in range(len(bloecke)):

        entschluesselterBlock = [0x0] * 16

        # decrypt each byte in the block
        for i in range(0, 16):
            n = char_entschluesseln(iv, bloecke, entschluesselterBlock, i)
            flag.insert(0, n)
            print(str(bytes(flag))[2:-1])

        # block entfernen nachdem voll entschlüsselt
        del bloecke[-1]

    # print the flag message
    print(f"\nDecrypted message: {bytes(flag)}")

if __name__ == "__main__":
    main()

#flag_bytes = b'This is your flag: flag{15de674f8c8aea5991a8410da27521ff4760}\n\n\x01'
