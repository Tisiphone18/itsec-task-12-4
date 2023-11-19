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

def decrypt_char(iv, blocks, decrypted_values, i):
    """Decrypts a single byte"""
    blocks_copy = blocks[:]
    iv_copy = iv

    #todo
    # calculate padding for i
    padding = ([0x0] * (15 - i)) + ([i + 1] * (i + 1))
    # xor padding with the previous decrypted values
    decripted_values_with_padding2 = [padding[i] ^ decrypted_values[i] for i in range(len(padding))]

    decripted_values_with_padding = [0x0] * 16
    for j in range(0, 16):
        if j < (15 - i):
            decripted_values_with_padding[j] = decrypted_values[j] ^ 0x00
        else:
            decripted_values_with_padding[j] = decrypted_values[j] ^ (i+1)


    # test padding for the i-th byte in the block
    for char in range(0, 256):
        # exclude the case, where evil is 0x0 (trivially true)
        if char != i + 1:

            # value to be XORed with the block
            aux = [0x0] * (15 - i) + [char] + [0x0] * i
            evil = [decripted_values_with_padding[i] ^ aux[i] for i in range(len(decripted_values_with_padding))]

            # xor the block (or the iv) with the evil value
            if (len(blocks) == 1):
                aux2 = bytes([(iv[i] ^ (evil[i])) for i in range(len(iv))])
                iv_copy = aux2
            else:
                aux2 = bytes([(blocks[-2][i] ^ (evil[i])) for i in range(len(blocks[-2]))])
                blocks_copy[-2] = aux2

            # check if the padding is valid

            s = socket.socket()
            s.connect(("itsec.sec.in.tum.de", 7023))

            start = read_until(s, b"Do you")
            s.send(binascii.hexlify(iv_copy) + b"\n")
            s.send(binascii.hexlify(b''.join(blocks_copy)) + b"\n")
            response = read_until(s, b"\n")
            if b"OK" in response:
                decrypted_values[15 - i] = char
                return char

    # if no valid padding found, it is the value we skipped before
    decrypted_values[15 - i] = i + 1
    return i + 1


def decypt_block(iv, blocks, decrypted):
    """Decrypts a single block"""
    decrypted_values = [0x0] * 16

    # decrypt each byte in the block
    for i in range(0, 16):
        n = decrypt_char(iv, blocks, decrypted_values, i)
        decrypted.insert(0, n)
        print(str(bytes(decrypted))[2:-1])

def main():
    decrypted = []

    # divide the message into blocks of 16 bytes
    blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)]

    # decrypt blocks
    for i in range(len(blocks)):
        decypt_block(iv, blocks, decrypted)
        # block entfernen nachdem voll entschlüsselt
        del blocks[-1]

    # print the decrypted message
    print(f"\nDecrypted message: {bytes(decrypted)}")

if __name__ == "__main__":
    main()

#flag_bytes = b'This is your flag: flag{15de674f8c8aea5991a8410da27521ff4760}\n\n\x01'
