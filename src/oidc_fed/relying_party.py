import json
from typing import Mapping, Sequence

from Crypto.PublicKey import RSA
from jwkest import JWKESTException
from jwkest.jwk import RSAKey, Key, keyrep
from jwkest.jws import JWS
from oic.oauth2.message import NotAllowedValue, MissingRequiredAttribute
from oic.oic import Client
from oic.utils.keyio import KeyJar, KeyBundle

from oidc_fed import OIDCFederationError
from oidc_fed.messages import FederationProviderConfigurationResponse


class RP(object):
    def __init__(self, root_key: Key, software_statements: Sequence[str],
                 federation_keys: Sequence[Key]) -> None:
        """
        :param root_key: root signing key for this RP
        :param software_statements: all software statements isssued by federations for this RP
        :param federation_keys: public keys from all federations this RP is part of
        """
        self.root_key = root_key
        self.software_statements = software_statements
        self.federation_keys = federation_keys
        self.client = Client()
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

    def get_provider_configuration(self, issuer: str) -> FederationProviderConfigurationResponse:
        """
        Fetch provider configuration information.

        The provider configuration is validated, ensuring the RP and the provider are part of a
        common federation, and verifying all signatures.
        :param issuer: issuer to fetch configuration information from
        :return: provider configuration information
        """
        provider_config = self.client.provider_config(issuer, keys=False,
                                                      response_cls=FederationProviderConfigurationResponse)
        provider_config = self._validate_provider_configuration(provider_config)

        return provider_config

    def _validate_provider_configuration(self,
                                         provider_config: FederationProviderConfigurationResponse) \
            -> FederationProviderConfigurationResponse:
        """
        Verify the provider configuration response.

        :param provider_config: provider configuration response from the provider
        :raise OIDCFederationError: if the provider configuration could not be validated
        :return: updated provider configuration
        """
        try:
            provider_config.verify()
        except (MissingRequiredAttribute, NotAllowedValue) as e:
            raise OIDCFederationError("Error in provider configuration: {}.".format(str(e)))

        provider_software_statement = self._verify_software_statements(
                provider_config["software_statements"])

        provider_root_key = keyrep(json.loads(provider_software_statement["root_key"]))
        provider_signing_key = self._verify_provider_signing_key(provider_config["signing_key"],
                                                                 provider_root_key)
        signed_provider_metadata = self._verify_signed_provider_metadata(
                provider_config["signed_metadata"], provider_signing_key)

        provider_config.update(signed_provider_metadata)
        return provider_config

    def _verify_software_statements(self, provider_software_statements: Sequence[str]) -> dict:
        """
        Find and verify the signature of the first software statement issued by a common federation.

        :param provider_software_statements: all software statements the provider presented in the
         provider configuration response.
        :raise OIDCFederationError: if no software statement has been issued by a common federation
        :return: payload of the first software statement issued by a common federation
        """
        for jws in provider_software_statements:
            try:
                return self._verify(jws, self.federation_keys)
            except JWKESTException as e:
                pass

        raise OIDCFederationError(
                "No software statement from provider issued by common federation.")

    def _verify_provider_signing_key(self, provider_signing_key: str, verification_key: Key) -> Key:
        """
        Verify the signature of the providers intermediary signing key.

        :param provider_signing_key: JWS containing the providers intermediary key
        :param verification_key: key to verify the signature with
        :raise OIDCFederationError: if the signature could not be verified
        :return: key contained in the JWS
        """
        try:
            signing_key = self._verify(provider_signing_key, keys=[verification_key])
        except JWKESTException as e:
            raise OIDCFederationError("The provider's signing key could not be verified.")

        return keyrep(signing_key)

    def _verify_signed_provider_metadata(self, signed_metadata: str,
                                         provider_signing_key: Key) -> dict:
        """
        Verify the signature of the signed metadata from the provider.

        :param signed_metadata: JWS containing the provider metadata
        :param provider_signing_key: key to verify the signature with
        :raise OIDCFederationError: if the signature could not be verified
        :return: provider metadata from the JWS
        """
        try:
            return self._verify(signed_metadata, [provider_signing_key])
        except JWKESTException as e:
            raise OIDCFederationError("The provider's signed metadata could not be verified.")

    def _sign(self, data: Mapping, key: Key) -> str:
        """
        Create a JWS containing the data, signed with key.

        :param data: data to sign
        :param key: key to use for signature
        :return: JWS containing the data
        """
        return JWS(json.dumps(data), alg=key.alg).sign_compact(keys=[key])

    def _verify(self, jws: str, keys: Sequence[Key]) -> dict:
        """
        Verify signature of JWS.

        :param jws: JWS to verify signature of
        :param keys: possible keys to verify the signature with
        :return: payload of the JWS
        """
        return JWS().verify_compact(jws, keys=keys)
