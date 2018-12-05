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


HOST = "LOCALHOST"
PORT = 6666

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


def connect(g, private_key, y, p):
    pn = dh.DHParameterNumbers(p, g)
    # print(p)
    # print(g)
    # print("Client y", y)
    g_bytes = easy_bytes(g)
    y_bytes = easy_bytes(y)
    p_bytes = easy_bytes(p)

    s = socket.socket()
    s.connect((HOST, PORT))
    print(f'Connected to {HOST}')

    s.send(g_bytes)
    g_len = int.from_bytes(s.recv(1024), byteorder='little')
    if g_len != len(g_bytes):
        s.close()
        exit(-1)

    s.send(y_bytes)
    pk_len = int.from_bytes(s.recv(1024), byteorder='little')
    if pk_len != len(y_bytes):
        s.close()
        exit(-1)

    s.send(p_bytes)
    mod_len = int.from_bytes(s.recv(1024), byteorder='little')
    if mod_len != len(p_bytes):
        s.close()
        exit(-1)

    peer_y_data = s.recv(1024)
    s.send(easy_bytes(len(peer_y_data)))
    peer_y = int.from_bytes(peer_y_data, byteorder='little')
    # print("Server y", peer_y)
    peer_public_numbers = dh.DHPublicNumbers(peer_y, pn)
    peer_public_key = peer_public_numbers.public_key(default_backend())
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    print("MITM Protection:", *random_emoji(int.from_bytes(derived_key,
                                                           byteorder='little'), UNICODE_VERSION), sep=' ')
    # print(derived_key)
    return s, derived_key


def generate():
    g = 0x2
    k = 0x200
    print(f'Generating secrets')
    parameters = dh.generate_parameters(
        generator=g, key_size=k, backend=default_backend())

    private_key = parameters.generate_private_key()
    p = parameters.parameter_numbers().p
    y = private_key.public_key().public_numbers().y
    return g, private_key, y, p


def chat(s, key):
    f = Fernet(base64.b64encode(key))
    while True:
        m = s.recv(1024)
        # print(m)
        print("Received:", f.decrypt(m).decode('utf-8'))
        to_send = input("Message: ")
        s.send(f.encrypt(bytes(to_send, 'utf-8')))


if __name__ == "__main__":
    g, a, y, p = generate()
    s, key = connect(g, a, y, p)
    chat(s, key)
