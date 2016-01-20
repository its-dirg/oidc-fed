import json

from jwkest import JWKESTException
from jwkest.jwk import keyrep
from oic.oauth2.message import NotAllowedValue, MissingRequiredAttribute
from oic.oic import Client

from oidc_fed import OIDCFederationError, OIDCFederationEntity
from oidc_fed.messages import FederationProviderConfigurationResponse
from oidc_fed.util import KeyJarWithSignedKeyBundles


class RP(OIDCFederationEntity):
    def __init__(self, root_key, software_statements, federation_keys, signed_jwks_uri):
        # type: (Key, Sequence[str], Sequence[Key], str) -> None
        """
        :param root_key: root signing key for this RP
        :param software_statements: all software statements isssued by federations for this RP
        :param federation_keys: public keys from all federations this RP is part of
        :param signed_jwks_uri: URL endpoint where the signed JWKS is published
        """
        super(RP, self).__init__(root_key, software_statements, federation_keys , signed_jwks_uri)

        self.client = Client()
        self.client.keyjar = KeyJarWithSignedKeyBundles()

    def get_provider_configuration(self, issuer):
        # type: (str) -> FederationProviderConfigurationResponse
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
        self.client.keyjar.load_keys(provider_config["signed_jwks_uri"], provider_config["issuer"],
                                     provider_config["signing_key"])

        return provider_config

    def _validate_provider_configuration(self, provider_config):
        # type: (FederationProviderConfigurationResponse) -> FederationProviderConfigurationResponse
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
        provider_config["signing_key"] = provider_signing_key
        try:
            # only use 'signed_jwks_uri'
            del provider_config["jwks_uri"]
            del provider_config["jwks"]
        except KeyError:
            pass

        return provider_config

    def _verify_software_statements(self, provider_software_statements):
        # type: (Sequence[str]) -> Dict[str, Union[str, List[str]]]
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

    def _verify_provider_signing_key(self, provider_signing_key, verification_key):
        # type: (str, Key) -> Key
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

    def _verify_signed_provider_metadata(self, signed_metadata, provider_signing_key):
        # type (str, Key) -> Dict[str, Union[str, List[str]]]
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
