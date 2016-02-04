"""
    oidc-fed
    ~~~~~~~~~~~~~~~~
    Example implementation of model for OpenID Connect federations.
    :copyright: (c) 2016 by Umeå University.
    :license: APACHE 2.0, see LICENSE for more details.
"""
import json
import uuid

from Crypto.PublicKey import RSA
from jwkest import JWKESTException
from jwkest.jwk import RSAKey, keyrep
from jwkest.jws import JWS
from oic.utils.keyio import KeyJar, KeyBundle


class OIDCFederationError(Exception):
    pass


class OIDCFederationEntity(object):
    def __init__(self, name, root_key, software_statements, federation_keys, signed_jwks_uri):
        # type: (str, Key, Sequence[str], Sequence[Key], str) -> None
        """
        :param name: URI identifying the entity
        :param root_key: root signing key for this entity
        :param software_statements: all software statements isssued by federations for this entity
        :param federation_keys: public keys from all federations this entity is part of
        :param signed_jwks_uri: URL endpoint where the signed JWKS is published
        """

        verify_signing_key(root_key)
        self.root_key = root_key

        self.name = name

        self.software_statements = [self._verify(ss, federation_keys) for ss in software_statements]
        self.federation_keys = federation_keys
        self.signed_jwks_uri = signed_jwks_uri

        self.intermediate_key = None
        self.jwks = None

        self.rotate_intermediate_key()
        self.rotate_jwks()

    @property
    def signed_intermediate_key(self):
        # type: () -> str
        """
        :return: JWS containing the intermediate key
        """
        return self._sign(self.intermediate_key.serialize(private=False), self.root_key)

    @property
    def signed_jwks(self):
        # type: () -> str
        """
        :return: JWS containing the JWKS
        """
        return self._sign(self.jwks.export_jwks(), self.intermediate_key)

    @property
    def software_statements_jws(self):
        # type: () -> List[str]
        """
        :return: all the entity's software statements as JWS
        """
        return [ss.jwt.pack() for ss in self.software_statements]

    def rotate_intermediate_key(self):
        # type: () -> None
        """Replace the current intermediate key with a fresh one."""
        self.intermediate_key = RSAKey(key=RSA.generate(1024), use="sig", alg="RS256",
                                       kid=self._create_kid())

    def rotate_jwks(self):
        # type: () -> None
        """Replace the current JWKS with a fresh one."""
        self.jwks = KeyJar()
        kb = KeyBundle(keyusage=["enc", "sig"])
        kb.append(RSAKey(key=RSA.generate(1024), kid=self._create_kid()))
        self.jwks.add_kb("", kb)

    def _create_kid(self):
        # type () -> str
        """
        Create a scope (by the entity's name) key id.
        :return: a new key id
        """
        return "{}/{}".format(self.name, uuid.uuid4())

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
        unpacked = JWS()
        unpacked.verify_compact(jws, keys=keys)
        return unpacked

    def _verify_signature_chain(self, software_statements, signing_key):
        # type: (Sequence[str], str) -> Tuple[str, Key]
        """
        Verify the signature chain: signature of software statement (containing root key) and
        signature of a signing key (in the form of a JWS).

        :param software_statements: all software statements from the provider
        :param signing_key: the entity's intermediate signing key
        :return:
        """
        software_statement = self._verify_software_statements(software_statements)

        root_key = keyrep(software_statement.msg["root_key"])
        signing_key = self._verify_signing_key(signing_key, root_key)
        return software_statement, signing_key

    def _verify_signing_key(self, signing_key, verification_key):
        # type: (str, Key) -> Key
        """
        Verify the signature of an intermediate signing key.

        :param signing_key: JWS containing the providers intermediate key
        :param verification_key: key to verify the signature with
        :raise OIDCFederationError: if the signature could not be verified
        :return: key contained in the JWS
        """
        try:
            signing_key = self._verify(signing_key, keys=[verification_key]).msg
        except JWKESTException as e:
            raise OIDCFederationError("The entity's signing key could not be verified.")

        return keyrep(signing_key)

    def _verify_software_statements(self, software_statements):
        # type: (Sequence[str]) -> Dict[str, Union[str, List[str]]]
        """
        Find and verify the signature of the first software statement issued by a common federation.

        :param software_statements: all software statements the entity presented in the
         metadata
        :raise OIDCFederationError: if no software statement has been issued by a common federation
        :return: payload of the first software statement issued by a common federation
        """
        for jws in software_statements:
            try:
                return self._verify(jws, self.federation_keys)
            except JWKESTException as e:
                pass

        raise OIDCFederationError("No software statement issued by known federation.")


def verify_signing_key(signing_key):
    if not signing_key.alg:
        raise OIDCFederationError("Specified signing key must have 'alg' set.")
    if not signing_key.kid:
        raise OIDCFederationError("Specified signing key must have 'kid' set.")
    if signing_key.use != "sig":
        raise OIDCFederationError("Specified signing key must have 'use=sig'.")
