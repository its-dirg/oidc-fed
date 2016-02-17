import json

from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey
from oic.oauth2 import rndstr


def generate_rsa_key(entity_name):
    return RSAKey(key=RSA.generate(2048), use="sig", alg="RS256",
                  kid="{}/{}".format(entity_name, rndstr()))


def load_software_statements(filepath):
    with open(filepath) as f:
        return [line.strip() for line in f]


def write_key_to_jwk(key, filepath):
    with open(filepath, "w") as f:
        f.write(json.dumps(key.serialize(private=False)))


def write_private_key_to_jwk(key, filepath):
    with open(filepath, "w") as f:
        f.write(json.dumps(key.serialize(private=True)))
