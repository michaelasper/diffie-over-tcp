import socket
import base64
import random
from bisect import bisect
from itertools import accumulate
from cryptography.fernet import Fernet
from unicodedata import name as unicode_name
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key

s = socket.socket()
host = "LOCALHOST"
port = 6666

# Set the unicode version.
# Your system may not support Unicode 7.0 charecters just yet! So hipster.
UNICODE_VERSION = 6

# Sauce: http://www.unicode.org/charts/PDF/U1F300.pdf
EMOJI_RANGES_UNICODE = {
    6: [
        ('\U0001F300', '\U0001F320'),
        ('\U0001F330', '\U0001F335'),
        ('\U0001F337', '\U0001F37C'),
        ('\U0001F380', '\U0001F393'),
        ('\U0001F3A0', '\U0001F3C4'),
        ('\U0001F3C6', '\U0001F3CA'),
        ('\U0001F3E0', '\U0001F3F0'),
        ('\U0001F400', '\U0001F43E'),
        ('\U0001F440', ),
        ('\U0001F442', '\U0001F4F7'),
        ('\U0001F4F9', '\U0001F4FC'),
        ('\U0001F500', '\U0001F53C'),
        ('\U0001F540', '\U0001F543'),
        ('\U0001F550', '\U0001F567'),
        ('\U0001F5FB', '\U0001F5FF')
    ],
    7: [
        ('\U0001F300', '\U0001F32C'),
        ('\U0001F330', '\U0001F37D'),
        ('\U0001F380', '\U0001F3CE'),
        ('\U0001F3D4', '\U0001F3F7'),
        ('\U0001F400', '\U0001F4FE'),
        ('\U0001F500', '\U0001F54A'),
        ('\U0001F550', '\U0001F579'),
        ('\U0001F57B', '\U0001F5A3'),
        ('\U0001F5A5', '\U0001F5FF')
    ],
    8: [
        ('\U0001F300', '\U0001F579'),
        ('\U0001F57B', '\U0001F5A3'),
        ('\U0001F5A5', '\U0001F5FF')
    ]
}

NO_NAME_ERROR = '(No name found for this codepoint)'


def random_emoji(key, unicode_version=6):
    if unicode_version in EMOJI_RANGES_UNICODE:
        emoji_ranges = EMOJI_RANGES_UNICODE[unicode_version]
    else:
        emoji_ranges = EMOJI_RANGES_UNICODE[-1]

    # Weighted distribution
    count = [ord(r[-1]) - ord(r[0]) + 1 for r in emoji_ranges]
    weight_distr = list(accumulate(count))
    random.seed(key)

    # Get one point in the multiple ranges
    point1 = random.randrange(weight_distr[-1])
    point2 = random.randrange(weight_distr[-1])
    point3 = random.randrange(weight_distr[-1])
    point4 = random.randrange(weight_distr[-1])

    # Select the correct range
    emoji_range_idx1 = bisect(weight_distr, point1)
    emoji_range1 = emoji_ranges[emoji_range_idx1]

    emoji_range_idx2 = bisect(weight_distr, point2)
    emoji_range2 = emoji_ranges[emoji_range_idx2]

    emoji_range_idx3 = bisect(weight_distr, point3)
    emoji_range3 = emoji_ranges[emoji_range_idx3]

    emoji_range_idx4 = bisect(weight_distr, point4)
    emoji_range4 = emoji_ranges[emoji_range_idx4]

    # Calculate the index in the selected range
    point_in_range1 = point1
    if emoji_range_idx1 is not 0:
        point_in_range1 = point1 - weight_distr[emoji_range_idx1 - 1]
    point_in_range2 = point2
    if emoji_range_idx2 is not 0:
        point_in_range2 = point2 - weight_distr[emoji_range_idx2 - 1]
    point_in_range3 = point3
    if emoji_range_idx3 is not 0:
        point_in_range3 = point3 - weight_distr[emoji_range_idx3 - 1]
    point_in_range4 = point4
    if emoji_range_idx4 is not 0:
        point_in_range4 = point4 - weight_distr[emoji_range_idx4 - 1]

    # Emoji 😄
    emoji1 = chr(ord(emoji_range1[0]) + point_in_range1)
    emoji2 = chr(ord(emoji_range2[0]) + point_in_range2)
    emoji3 = chr(ord(emoji_range3[0]) + point_in_range3)
    emoji4 = chr(ord(emoji_range4[0]) + point_in_range4)

    return (emoji1, emoji2, emoji3, emoji4)


def easy_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='little')


# this connection has to be opened up first
s.bind((host, port))
s.listen(5)

c = None
global_key = None
secrets = False
f = None
while True:
    if c is None:
        # gotta wait on other connection
        print('Waiting on other user to connect...')
        c, addr = s.accept()
        print(f'User has connected at {addr}')
    elif secrets:
        if f is None:
            f = Fernet(base64.b64encode(global_key))
        to_send = input("Message: ")
        c.send(f.encrypt(bytes(to_send, 'utf-8')))
        message = c.recv(1024)
        print("Received:", f.decrypt(message).decode('utf-8'))

    else:
        print('Waiting on public paramaters')
        # g
        g_data = c.recv(1024)
        c.send(easy_bytes(len(g_data)))

        # g^a
        y_data = c.recv(1024)
        c.send(easy_bytes(len(y_data)))

        # p
        modulus_data = c.recv(1024)
        c.send(easy_bytes(len(modulus_data)))

        # math
        p = int.from_bytes(modulus_data, byteorder='little')
        g = int.from_bytes(g_data, byteorder='little')
        y = int.from_bytes(y_data, byteorder='little')

        pn = dh.DHParameterNumbers(p, g)
        # print(p)
        # print(g)
        parameters = pn.parameters(default_backend())
        private_key = parameters.generate_private_key()
        y_2 = private_key.public_key().public_numbers().y
        # print("Server y", y_2)
        # print("Client y", y)

        c.send(easy_bytes(y_2))
        pk_len = int.from_bytes(c.recv(1024), byteorder='little')
        if pk_len != len(easy_bytes(y_2)):
            print("mismatched data")
            s.close()
            exit(-1)

        peer_public_numbers = dh.DHPublicNumbers(y, pn)
        peer_public_key = peer_public_numbers.public_key(default_backend())
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        global_key = derived_key

        print("MITM Protection:", *random_emoji(int.from_bytes(derived_key,
                                                               byteorder='little'), UNICODE_VERSION), sep=' ')
    # g^b

        secrets = True


s.close()
