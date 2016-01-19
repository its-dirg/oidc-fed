import json

from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey, Key
from jwkest.jws import JWS
from oic.utils.keyio import KeyJar, KeyBundle


class RP(object):
    def __init__(self, root_key: Key) -> None:
        self.root_key = root_key
        self.intermediary_key = None
        self.jwks = None

        self.rotate_intermediary_key()
        self.rotate_jwks()

    @property
    def signed_intermediary_key(self) -> str:
        """
        :return: JWS containing the intermediary key
        """
        return self._sign(self.intermediary_key.serialize(private=False), self.root_key)

    @property
    def signed_jwks(self) -> str:
        """
        :return: JWS containing the JWKS
        """
        return self._sign(self.jwks.export_jwks(), self.intermediary_key)

    def rotate_intermediary_key(self) -> None:
        """Replace the current intermediary key with a fresh one."""
        self.intermediary_key = RSAKey(key=RSA.generate(1024), use="sig", alg="RS256")

    def rotate_jwks(self) -> None:
        """Replace the current JWKS with a fresh one."""
        self.jwks = KeyJar()
        kb = KeyBundle(keyusage=["enc", "sig"])
        kb.append(RSAKey(key=RSA.generate(1024)))
        self.jwks.add_kb("", kb)

    def _sign(self, data: dict, key: Key) -> str:
        """
        Create a JWS containing the data, signed with key.

        :param data: data to sign
        :param key: key to use for signature
        :return: JWS containing the data
        """
        return JWS(json.dumps(data), alg=key.alg).sign_compact(keys=[key])
