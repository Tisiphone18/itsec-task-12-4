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

def char_entschluesseln(blocks, entschluesselte_werte, i):
    for char in range(0, 256):
        if char != i + 1:

            blocks_permuted = blocks[:]
            iv_permuted = iv

            if len(blocks) == 1:

                for j in range(0, 16):
                    if j < (15 - i):
                        iv_permuted[j] = entschluesselte_werte[j] ^ iv[j]
                    elif j == (15 - i):
                        iv_permuted[j] = entschluesselte_werte[j] ^ (i + 1) ^ char ^ iv[j]
                    else:
                        iv_permuted[j] = entschluesselte_werte[j] ^ (i + 1) ^ 0x00 ^ iv[j]

            else:

                angriffsvektor = [0x0] * 16
                for j in range(0, 16):
                    if j < (15 - i):
                        angriffsvektor[j] = entschluesselte_werte[j]
                    elif j == (15 - i):
                        angriffsvektor[j] = entschluesselte_werte[j] ^ (i + 1) ^ char
                    else:
                        angriffsvektor[j] = entschluesselte_werte[j] ^ (i + 1) ^ 0x00

                blocks_permuted[-2] = bytes([(blocks[-2][i] ^ (angriffsvektor[i])) for i in range(len(blocks[-2]))])

            s = socket.socket()
            s.connect(("itsec.sec.in.tum.de", 7023))
            start = read_until(s, b"Do you")
            s.send(binascii.hexlify(iv_permuted) + b"\n")
            s.send(binascii.hexlify(b''.join(blocks_permuted)) + b"\n")
            response = read_until(s, b"\n")

            if b"OK" in response:
                entschluesselte_werte[15 - i] = char
                return char

    entschluesselte_werte[15 - i] = i + 1
    return i + 1

#Los

flag = []
bloecke = []

for i in range(0, len(msg), 16):
    block = msg[i:i + 16]
    bloecke.append(block)

# blöcke entschlüsseln
for b_nr in range(0, 4):

    entschluesselterBlock = [0x0] * 16

    # jedes einzelne Byte entschlüsseln
    for i in range(0, 16):
        n = char_entschluesseln(bloecke, entschluesselterBlock, i)
        print(str(bytes(entschluesselterBlock[::-1]))[2:-1])
        flag.insert(0, n)

    # hintersten block entfernen nachdem voll entschlüsselt
    del bloecke[-1]

# print the flag message
print(bytes(flag))


# flag_bytes = b'This is your flag: flag{15de674f8c8aea5991a8410da27521ff4760}\n\n\x01'
