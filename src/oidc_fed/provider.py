from oic.oic.provider import Provider

from oidc_fed import OIDCFederationEntity
from oidc_fed.messages import FederationProviderConfigurationResponse


class OP(OIDCFederationEntity):
    def __init__(self, issuer, root_key, software_statements, federation_keys, signed_jwks_uri,
                 jwks_uri=None):
        # type: (str, Key, Sequence[str], Sequence[Key], str, Optional[str]) -> None
        """
        :param issuer: issuer URL for this provider
        :param root_key: root signing key for this OP
        :param software_statements: all software statements isssued by federations for this OP
        :param federation_keys: public keys from all federations this OP is part of
        :param signed_jwks_uri: URL endpoint where the signed JWKS is published
        :param jwks_uri: URL endpoint where the JWKS is published
        """
        super(OP, self).__init__(root_key, software_statements, federation_keys, signed_jwks_uri)
        self.provider = Provider(issuer, None, None, None, None, None, None, None)
        self.provider.jwks_uri = jwks_uri

    def provider_configuration(self):
        # type: () -> FederationProviderConfigurationResponse
        """
        Generate the provider configuration information.
        :return: the provider configuration information
        """
        extra_params = dict(software_statements=[self._recreate_software_statement(ss) for ss in
                                                 self.software_statements],
                            signing_key=self.signed_intermediary_key,
                            signed_jwks_uri=self.signed_jwks_uri)
        provider_config = self.provider.create_providerinfo(
                pcr_class=FederationProviderConfigurationResponse, setup=extra_params)
        provider_config["signed_metadata"] = self._sign(provider_config.to_dict(), self.intermediary_key)

        return provider_config
