import json

from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey
from oic import rndstr


def generate_rsa_key(entity_name):
    return RSAKey(key=RSA.generate(2048), use="sig", alg="RS256",
                  kid="{}/{}".format(entity_name, rndstr()))


def write_key_to_jwk(key, filepath, pretty_format=False):
    _write_key_to_jwk(key, filepath, False, pretty_format)


def write_private_key_to_jwk(key, filepath, pretty_format=False):
    _write_key_to_jwk(key, filepath, True, pretty_format)


def _write_key_to_jwk(key, filepath, private, pretty_format=False):
    indent = None
    if pretty_format:
        indent = 0

    with open(filepath, "w") as f:
        f.write(json.dumps(key.serialize(private=private), indent=indent, sort_keys=True))
