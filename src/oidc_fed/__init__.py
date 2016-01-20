"""
    oidc-fed
    ~~~~~~~~~~~~~~~~
    Example implementation of model for OpenID Connect federations.
    :copyright: (c) 2016 by Umeå University.
    :license: APACHE 2.0, see LICENSE for more details.
"""
import json

from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey
from jwkest.jws import JWS
from oic.utils.keyio import KeyJar, KeyBundle


class OIDCFederationError(Exception):
    pass


class OIDCFederationEntity(object):
    def __init__(self, root_key, software_statements, federation_keys, signed_jwks_uri):
        # type: (Key, Sequence[str], Sequence[Key], str) -> None
        """
        :param root_key: root signing key for this entity
        :param software_statements: all software statements isssued by federations for this entity
        :param federation_keys: public keys from all federations this entity is part of
        :param signed_jwks_uri: URL endpoint where the signed JWKS is published
        """
        self.root_key = root_key
        self.software_statements = software_statements
        self.federation_keys = federation_keys
        self.signed_jwks_uri = signed_jwks_uri

        self.intermediary_key = None
        self.jwks = None

        self.rotate_intermediary_key()
        self.rotate_jwks()

    @property
    def signed_intermediary_key(self):
        # type: () -> str
        """
        :return: JWS containing the intermediary key
        """
        return self._sign(self.intermediary_key.serialize(private=False), self.root_key)

    @property
    def signed_jwks(self):
        # type: () -> str
        """
        :return: JWS containing the JWKS
        """
        return self._sign(self.jwks.export_jwks(), self.intermediary_key)

    def rotate_intermediary_key(self):
        # type: () -> None
        """Replace the current intermediary key with a fresh one."""
        self.intermediary_key = RSAKey(key=RSA.generate(1024), use="sig", alg="RS256")

    def rotate_jwks(self):
        # type: () -> None
        """Replace the current JWKS with a fresh one."""
        self.jwks = KeyJar()
        kb = KeyBundle(keyusage=["enc", "sig"])
        kb.append(RSAKey(key=RSA.generate(1024)))
        self.jwks.add_kb("", kb)

    def _sign(self, data, key):
        # type: (Mapping[str, Union[str, Sequence[str]]], Key) -> str
        """
        Create a JWS containing the data, signed with key.

        :param data: data to sign
        :param key: key to use for signature
        :return: JWS containing the data
        """
        return JWS(json.dumps(data), alg=key.alg).sign_compact(keys=[key])

    def _verify(self, jws, keys):
        # type: (str, Sequence[Key]) -> Dict[str, Union[str, Lists[str]]]
        """
        Verify signature of JWS.

        :param jws: JWS to verify signature of
        :param keys: possible keys to verify the signature with
        :return: payload of the JWS
        """
        return JWS().verify_compact(jws, keys=keys)
