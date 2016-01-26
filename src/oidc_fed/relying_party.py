import logging

import requests
from jwkest import JWKESTException
from oic.exception import MessageException
from oic.extension.signed_http_req import SignedHttpRequest

from oidc_fed import OIDCFederationError, OIDCFederationEntity
from oidc_fed.messages import (FederationProviderConfigurationResponse,
                               FederationRegistrationRequest,
                               FederationRegistrationResponse)
from oidc_fed.util import FederationClient

logger = logging.getLogger(__name__)


class RP(OIDCFederationEntity):
    def __init__(self, root_key, software_statements, federation_keys, signed_jwks_uri):
        # type: (Key, Sequence[str], Sequence[Key], str) -> None
        """
        :param root_key: root signing key for this RP
        :param software_statements: all software statements isssued by federations for this RP
        :param federation_keys: public keys from all federations this RP is part of
        :param signed_jwks_uri: URL endpoint where the signed JWKS is published
        """
        super(RP, self).__init__(root_key, software_statements, federation_keys, signed_jwks_uri)

        self.client = FederationClient()

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
        self.client.provider_info = self._validate_provider_configuration(provider_config)

        return self.client.provider_info

    def register_with_provider(self, issuer, client_registration_data):
        # type (str, Mapping[str, Any]) -> None
        """
        Register client with a provider.

        :param issuer: issuer URL for the provider to register with
        :param client_registration_data: client metadata to send in the registration request
        """
        if not self.client.provider_info or self.client.provider_info["issuer"] != issuer:
            self.get_provider_configuration(issuer)

        reg_req = self._create_registration_request(client_registration_data)
        headers = {"Content-Type": "application/jose"}
        request_data = self._sign_registration_request(reg_req)
        try:
            http_resp = requests.post(self.client.provider_info["registration_endpoint"],
                                      request_data, headers=headers)
        except requests.ConnectionError as e:
            raise OIDCFederationError("Could send registration request to {}".format(issuer))

        logger.debug("Registration response from %s; status %s, Content-Type %s", http_resp.url,
                     http_resp.status_code, http_resp.headers["Content-Type"])

        registration_response = FederationRegistrationResponse(**http_resp.json())
        try:
            registration_response.verify()
        except MessageException as e:
            raise OIDCFederationError("Error in registration response: {}.".format(str(e)))

        self._handle_registration_response(registration_response)

    def _handle_registration_response(self, registration_response):
        # type: (requests.Response) -> None
        """
        Verify and store the registration response.

        Also sets self.client.provider_signing_key.
        :param registration_response: registration response from the provider
        """
        provider_software_statement, provider_signing_key = self._verify_signature_chain(
                [registration_response["provider_software_statement"]],
                self.client.provider_info["signing_key"])

        provider_metadata = {k: v for k, v in provider_software_statement.msg.items() if
                             k in FederationProviderConfigurationResponse.c_param}
        self.client.provider_info.update(provider_metadata)
        self.client.provider_signing_key = provider_signing_key
        self.client.store_registration_info(registration_response)

        self.client.keyjar.load_keys(self.client.provider_info["signed_jwks_uri"],
                                     self.client.provider_info["issuer"],
                                     provider_signing_key)

    def _create_registration_request(self, client_registration_data):
        # type: (Mapping[str, Any] ) -> FederationRegistrationRequest
        """
        Create registration request.

        :param client_registration_data: client metadata to send in the request
        :return: registration request
        """
        registration_request = FederationRegistrationRequest(**client_registration_data)
        registration_request["signed_jwks_uri"] = self.signed_jwks_uri
        registration_request["signing_key"] = self.signed_intermediary_key
        registration_request["software_statements"] = [self._recreate_software_statement(ss) for ss
                                                       in self.software_statements]
        return registration_request

    def _sign_registration_request(self, registration_request):
        # type (FederationRegistrationRequest) -> str
        """
        Sign registration request.

        :param registration_request: registration request
        :return: signed registration request
        """
        signer = SignedHttpRequest(self.intermediary_key)
        return signer.sign(self.intermediary_key.alg, body=registration_request.to_json())

    def _validate_provider_configuration(self, provider_config):
        # type: (FederationProviderConfigurationResponse) -> FederationProviderConfigurationResponse
        """
        Verify the provider configuration response.

        :param provider_config: provider configuration response from the provider
        :raise OIDCFederationError: if the provider configuration could not be validated
        :return: updated provider configuration and the provider's signing key
        """
        try:
            provider_config.verify()
        except MessageException as e:
            raise OIDCFederationError("Error in provider configuration: {}.".format(str(e)))

        _, provider_signing_key = self._verify_signature_chain(
                provider_config["software_statements"],
                provider_config["signing_key"])
        signed_provider_metadata = self._verify_signed_provider_metadata(
                provider_config["signed_metadata"], provider_signing_key)

        provider_config.update(signed_provider_metadata)
        try:
            # only use 'signed_jwks_uri'
            del provider_config["jwks_uri"]
            del provider_config["jwks"]
        except KeyError:
            pass

        return provider_config

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
            return self._verify(signed_metadata, [provider_signing_key]).msg
        except JWKESTException as e:
            raise OIDCFederationError("The provider's signed metadata could not be verified.")
