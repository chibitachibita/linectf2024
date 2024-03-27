from socket import create_connection
import itertools
import binascii
import struct
import json
import math


class Tube:
    def __init__(s, host, port, debug=False):
        s.host = host
        s.port = port
        s.sock = create_connection((host, port))
        s.debug = debug

    def recv(s, size=1024) -> bytes:
        buf = s.sock.recv(size)
        if s.debug:
            print(f"[Tube#recv] {buf=}")
        return buf

    def recv_until(s, expected: bytes) -> bytes:
        buf = b""
        while True:
            buf += s.sock.recv(1)
            if expected in buf:
                break
        if s.debug:
            print(f"[Tube#recv_until] {buf=}")
        return buf

    def send(s, buf: bytes):
        if s.debug:
            print(f"[Tube#send] {buf=}")
        s.sock.send(buf)

    def send_line(s, buf: bytes):
        s.send(buf + b"\n")

    def close(s):
        s.sock.close()
        if s.debug:
            print("[Tube#close] closed")


def main():
    tube = Tube("34.146.137.8", "11223")

    def recv():
        return json.loads(tube.recv(16384).strip())

    def send(x):
        return tube.send(x)

    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def split_16(data: bytes) -> [bytes]:
        return [data[16 * n : 16 * (n + 1)] for n in range(math.ceil(len(data) / 16))]

    def decrypt_cfb(msg: bytes) -> [bytes]:
        msg += b"\x00" * max(
            256 - len(msg), (msg_block_len_in_hex + 32) // 2 - len(msg)
        )
        msg = binascii.hexlify(msg)

        assert len(msg) <= msg_block_len_in_hex + 32
        assert 512 < len(msg)
        assert len(msg) <= 1024

        send(msg)

        temp = recv()
        assert temp["msg"] == "CFB Decryption"
        return split_16(binascii.unhexlify(temp["ret"]))

    def decrypt_cbc(msg: bytes) -> [bytes]:
        msg += b"\x00" * min(
            max(256 - len(msg), msg_block_len_in_hex + 32 - len(msg)) + 16,
            512 - len(msg),
        )
        msg = binascii.hexlify(msg)

        assert msg_block_len_in_hex + 32 < len(msg)
        assert 512 < len(msg)
        assert len(msg) <= 1024

        send(msg)

        temp = recv()
        assert temp["msg"] == "CBC Decryption"
        return split_16(binascii.unhexlify(temp["ret"]))

    iv = binascii.unhexlify("5f885849eadbc8c7bce244f8548a443f")
    initial_data = recv()
    nonce = binascii.unhexlify(initial_data["nonce"])
    target_ciphertext = binascii.unhexlify(initial_data["ct"])

    ct_len_in_byte = len(target_ciphertext)
    msg_block_len_in_hex = (16 * (math.ceil(ct_len_in_byte / 16))) * 2

    # pinを含むmsgを暗号化したものを16byte毎に分割（ブロック鍵暗号方式が1ブロックあたり16byteだから）
    blocks = split_16(target_ciphertext)

    keys = []
    for i in range(len(blocks)):
        keys.append(nonce + struct.pack(">I", i + 2))
        
        # keys配列の末尾の文字列長が16であること
        assert len(keys[-1]) == 16

    cts = []
    encrypted_key_candidates = []
    for i in range(0, len(keys), 10):
        cts = decrypt_cfb(
            # nonceの繰り返しを渡してる？かな
            # ex：「あいうえお」で暗号化して「あいうえお」で返ってくる候補を探してる？
            b"\x00" * 16 + b"".join(b"\x00" * 16 + key for key in keys[i : i + 10])
        )

        #　配列の3から末尾までを2文字ずつ連結する（鍵の候補？かな）
        encrypted_key_candidates += cts[3::2]

    print(f"[+] {encrypted_key_candidates = }")
    # print(len([xor(x, y) for x, y in zip(blocks, encrypted_key_candidates)][1:-3]))
    key_bruteforce_list = [
        bytes([0] * 14 + [x, y]) for x, y in itertools.product(range(256), repeat=2)
    ]
    encrypted_keys = []

    # 
    for i in range(1, len(keys) - 3):
        key_cand = encrypted_key_candidates[i]
        kp = keys[i]
        cur = 0
        while cur < len(key_bruteforce_list):
            kci_blocks = [xor(key_cand, b) for b in key_bruteforce_list[cur : cur + 25]]

            # 115行目で出した候補（encrypted_key_candidates）を今度CBCでやってる？
            cand = decrypt_cbc(b"".join(kci_blocks))

            # XORだ、、
            cand_xored = [xor(x, y) for x, y in zip(cand, [iv] + kci_blocks)]
            res = [i for i, b in enumerate(cand_xored) if b == kp]
            if len(res) > 0:
                encrypted_keys.append(kci_blocks[res[0]])
                break
            cur += 25

        print([xor(x, y) for x, y in zip(encrypted_keys, blocks[1:])])

    # なんで17文字と言い切れるのか
    assert len(encrypted_keys) == 17
    pin = b"".join(xor(x, y) for x, y in zip(encrypted_keys, blocks[1:]))[13:-3]

    tube.send(binascii.hexlify(pin))
    print(recv())

    tube.close()


if __name__ == "__main__":
    main()
