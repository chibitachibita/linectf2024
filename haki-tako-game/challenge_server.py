from crypto import generate_new_msg, check_pin, cbc_decrypt, truncated_cfb128_decrypt
import socket, signal, json, threading, math
from socketserver import BaseRequestHandler, TCPServer, ForkingMixIn

# 0.0.0.0=サイダー（サブネットマスク）
address = ('0.0.0.0', 11223)

LIMIT_PER_CONNECTION = 45000


class ChallengeHandler(BaseRequestHandler):

    def handle(self):
        signal.alarm(7200)
        req = self.request
        count = 0

        new_encrypted_msg, correct_pin, aes_key = generate_new_msg()

        # サーバー側に出るpin
        print('pin:',correct_pin.hex())

        new_encrypted_msg['msg'] = 'Send me ciphertext(hex) or pin-code.\nNew encrypted msg...'

        # ncしたレスポンス（req.sendall）
        # クライアント側でpinとか入力しない限りここで止まる
        req.sendall(json.dumps(new_encrypted_msg).encode('utf-8') + b"\n")

        # msg length in hex/block
        # 暗号文の長さ
        ct_len_in_byte = len(new_encrypted_msg['ct'])//2

        # 16進数のブロック数（AESはブロック暗号化方式　16byte毎のブロック暗号）
        # 16vyteごとに割って（ct_len_in_byte / 16）、切り捨て（math.cell） あとはなんかしてる
        msg_block_len_in_hex = (16*(math.ceil(ct_len_in_byte / 16)))*2
        while True:
            try:
                if count >= LIMIT_PER_CONNECTION:
                    ret = {
                        'error': 'Too many requests. Bye.'
                    }
                    req.sendall(json.dumps(ret).encode('utf-8') + b"\n")
                    break
                count += 1

                # 入力したものを受け取る（1024byte以上は切り捨てして、decode。改行は捨てる（strip()））
                req_msg = req.recv(1024).decode().strip()

                # 32 == 1block as hex string
                
                # 入力した文字数で挙動が変わる（結局送るときにencodeしてる）
                if len(req_msg) <= 512:
                    print(len(req_msg))
                    flag = check_pin(req_msg, correct_pin)

                    # 不正解ルート
                    if "" == flag:
                        ret = {
                            'msg': 'Incorrect pin. Bye.\n'
                        }
                        req.sendall(json.dumps(ret).encode('utf-8') + b"\n")
                    
                    # 正解ルート
                    else:
                        ret = {
                            'flag': flag
                        }
                        req.sendall(json.dumps(ret).encode('utf-8') + b'\n')
                    
                    # このbreakがなければpin自体のブルートフォースを45,000回できる pinの総当りを45,000回ためせた
                    break  # Prevent Brute Force

                # ここはbreakないからたぶんここをうまく使えってこと（breakないから45,000回試せる）
                elif len(req_msg) <= msg_block_len_in_hex+32:
                    # CFBもAESの中の暗号化方式 GCMの友達
                    # 鍵をあけるためのヒント（同じAESのGCM方式で暗号化したaes_keyを使って復号化しているから）
                    ret = truncated_cfb128_decrypt(bytes.fromhex(req_msg), aes_key)

                    ret['msg'] = 'CFB Decryption'
                    req.sendall(json.dumps(ret).encode('utf-8') + b"\n")
                else:
                    # CBCも同上 AESのともだち
                    # 鍵をあけるためのヒント（同じAESのGCM方式で暗号化したaes_keyを使って復号化しているから）
                    ret = cbc_decrypt(bytes.fromhex(req_msg), aes_key)

                    ret['msg'] = 'CBC Decryption'
                    req.sendall(json.dumps(ret).encode('utf-8') + b'\n')
                    
            except socket.timeout:
                ret = {
                    'error': 'Timeout. Bye.\n'
                }
                req.sendall(json.dumps(ret).encode('utf-8') + b"\n")
                break
            except socket.error:
                break
            except Exception as e:
                break


class ChallengeServer(ForkingMixIn, TCPServer):
    request_queue_size = 100

    # For address reassignment on reboot
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

# 一番最初に実行される
# 直接実行されるときだけ通る ずっとサーバーを立ち上げておくための処理
if __name__ == "__main__":
    TCPServer.allow_reuse_address = True
    server = ChallengeServer(address, ChallengeHandler)
    server.serve_forever()

    with server:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.setDaemon(True)
        server_thread.start()
        while True:
            pass
