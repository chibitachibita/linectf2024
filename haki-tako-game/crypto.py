#!/usr/bin/env python3

# crypto challenge

import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), './secret/'))
from server_secret import FLAG, MSG_FORMAT #ローカルで作る
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# あんま関係なかったかもわからない
AES_IV_HEX = "5f885849eadbc8c7bce244f8548a443f"

aes_iv = bytes.fromhex(AES_IV_HEX)

def cbc_decrypt(ciphertext, aes_key):
    cipher = AES.new(key=aes_key, mode=AES.MODE_CBC, iv=aes_iv)
    ret = {
        "ret": cipher.decrypt(ciphertext).hex()
    }
    return ret

def cfb128_decrypt(ciphertext, aes_key):
    cipher = AES.new(key=aes_key, mode=AES.MODE_CFB, iv=aes_iv, segment_size=128)
    ret = {
        "ret": cipher.decrypt(ciphertext).hex()
    }
    return ret

def truncated_cfb128_decrypt(ciphertext, aes_key):
    ret = cfb128_decrypt(ciphertext, aes_key)
    ret['ret'] = ret['ret'][:len(ret['ret'])-(len(ret['ret'])%32)]
    for i in range(32, len(ret['ret'])+1, 32):
        ret['ret'] = ret['ret'][:i-4]  + "0000" + ret['ret'][i:]
    return ret

# 答え（pin）が入ってるのはGCM方式でAESを使って暗号化してるお
def generate_new_msg():
    """クライアント側に返却するメッセージpinAESキーを生成"""
    aes_key = get_random_bytes(32) #AESキー生成
    pin = get_random_bytes(256) #PIN生成
    # バイナリ
    msg = b'Your authentication code is..' + pin + b'. Do not tell anyone and you should keep it secret!'
    return gcm_encrypt(msg, aes_key), pin, aes_key


def gcm_encrypt(plaintext, aes_key):
    nonce = get_random_bytes(12)
    # 暗号化にするためのオブジェクトを作ってる
    # GCM：AESの暗号化方式の名前
    # nonce = 乱数のこと
    cipher = AES.new(key=aes_key, mode=AES.MODE_GCM, nonce=nonce)

    # encrypt_and_digestは平文を渡して暗号文と暗号文（ciphertext）と署名（tag）を返してる
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    ret = {
        # 16進数に変換してjson作ってる
        "nonce": cipher.nonce.hex(),
        "ct": ciphertext.hex(),
        "tag": tag.hex()
    }
    return ret


def check_pin(pin, correct):
    if pin == correct.hex():
        return FLAG
    return ""

