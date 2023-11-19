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

def xor_block_with_list(block, list):
    """XORs a block with a list of bytes"""
    return bytes([(block[i] ^ (list[i])) for i in range(len(block))])


def char_entschluesseln(vektor, blocks, entschluesselter_block, stelle):

    padding = ([0x0] * (15 - stelle)) + ([stelle + 1] * (stelle + 1)) # [0,0,...,(i+1),(i+1)]
    entschlüsselte_Werte_mit_padding = [padding[i] ^ entschluesselter_block[i] for i in range(len(padding))]

    blocks_kopie = blocks[:]
    vector_kopie = vektor

    # alle chars durchlaufen
    for char in range(0, 256):
        if char != stelle + 1: # sonst Sonderfall !

            #xor Wert an Pos stelle mit char
            arr = [0x0] * (15 - stelle) + [char] + [0x0] * stelle
            angriffsvektor = [entschlüsselte_Werte_mit_padding[i] ^ arr[i] for i in range(len(entschlüsselte_Werte_mit_padding))]

            # xor den block (or den vector in der letzten Runde) mit dem angriffsvektor
            if len(blocks) == 1:
                #Vector mit angriffsvektor xorn
                vector_kopie = xor_block_with_list(vektor, angriffsvektor)
            else:
                # Forgängerblock mit angriffsvektor xorn
                blocks_kopie[-2] = xor_block_with_list(blocks[-2], angriffsvektor)

            #Nachricht zusammenfügen !
            ganzer_Block = ''.join('{:02x}'.format(byte) for byte in b''.join(blocks)).encode() + b'\n'

            s = socket.socket()
            s.connect(("itsec.sec.in.tum.de", 7023))
            start = read_until(s, b"Do you")
            s.send(binascii.hexlify(vector_kopie) + b"\n")
            s.send(ganzer_Block)
            response = read_until(s, b"\n")

            if b"OK" in response: #Wert speichern und aus Schleife
                entschluesselter_block[15 - stelle] = char
                return char

    # wenn kein valider Char existiert, dann Sonderfall
    char = stelle + 1
    entschluesselter_block[15 - stelle] = char
    return char

entschluesselter_Text = []

blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)]

# Blöcke entschlüsseln
for b in range(len(blocks)):

    entschluesselter_block = [0x0 for _ in range(16)]

    # jedes Byte im Block entschlüsseln
    for stelle in range(0, 16):
        char = char_entschluesseln(iv, blocks, entschluesselter_block, stelle)
        #todo append -> umdrehen !
        entschluesselter_Text.append(char)
        #todo
        print(str(bytes(entschluesselter_Text[::-1]))[2:-1])

    # letzten Block entfernen um weiter zumachen mit 16 byte kürzerer Nachricht
    del blocks[-1]

# entschlüsselte Flag:
print(f"\nMeine Flag ist: ", bytes(entschluesselter_Text))

#flag_bytes = b'This is your flag: flag{15de674f8c8aea5991a8410da27521ff4760}\n\n\x01'
