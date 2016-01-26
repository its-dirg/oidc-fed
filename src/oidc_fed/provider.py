import copy
import json

from oic.exception import MessageException
from oic.extension.signed_http_req import SignedHttpRequest, ValidationError
from oic.oic import PREFERENCE2PROVIDER
from oic.oic.provider import Provider
from oic.utils.http_util import Response

from oidc_fed import OIDCFederationEntity, OIDCFederationError
from oidc_fed.messages import FederationProviderConfigurationResponse, \
    FederationRegistrationRequest, \
    FederationRegistrationResponse


class OP(OIDCFederationEntity):
    def __init__(self, issuer, root_key, software_statements, federation_keys, signed_jwks_uri,
                 jwks_uri=None, capabilities=None):
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
        self.provider = Provider(issuer, None, {}, None, None, None, None, None,
                                 capabilities=capabilities)
        self.provider.jwks_uri = jwks_uri

        self.registration_verification = RegistrationRequestVerification()

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
        provider_config["signed_metadata"] = self._sign(provider_config.to_dict(),
                                                        self.intermediary_key)

        return provider_config

    def register_client(self, request_headers, request_body):
        # type (Mapping[str, str], str) -> Response
        """
        Process a signed registration request from a client.
        :param request_headers: HTTP request headers
        :param request_body: unpacked HTTP POST body
        :raise OIDCFederationError: if the registration request is malformed
        :return: the registered client metadata to return to the client
        """
        if "Authorization" not in request_headers:
            raise OIDCFederationError("Missing Authorization header in registration request.")
        if not request_headers["Authorization"].startswith("pop "):
            raise OIDCFederationError("Wrong Authentication scheme in registration request.")

        registration_request = FederationRegistrationRequest(**json.loads(request_body))
        registration_request.rm_blanks()

        try:
            registration_request.verify()
        except MessageException as e:
            raise OIDCFederationError("Error in client registration request: {}.".format(str(e)))

        client_software_statement, client_signing_key = self._verify_signature_chain(
                registration_request["software_statements"],
                registration_request["signing_key"])

        request_signature = request_headers["Authorization"][len("pop "):]
        try:
            SignedHttpRequest(client_signing_key).verify(request_signature, body=request_body)
        except ValidationError as e:
            raise OIDCFederationError("Could not verify signature of client registration request.")

        provider_software_statement = self._find_software_statement_for_federation(
                client_software_statement.jwt.headers["kid"])
        matched_preferences = self.registration_verification.verify(
                self.provider.capabilities.to_dict(), provider_software_statement.msg,
                registration_request.to_dict(), client_software_statement.msg)

        # recreate client registration request only with the common capabilities
        registration_request.update(matched_preferences)
        result = self.provider.client_registration_setup(registration_request)
        if isinstance(result, Response):
            return result

        registration_response = FederationRegistrationResponse(**result.to_dict())
        registration_response["provider_software_statement"] = self._recreate_software_statement(
                provider_software_statement)
        return registration_response

    def _find_software_statement_for_federation(self, federation_kid):
        # type: (str) -> Optional[JWS]
        """
        Find a software statement signed by the specified key id.
        :param federation_kid: key id to search for
        :return: the first occurrence of a software statement signed by the specified key id
        """
        for ss in self.software_statements:
            if ss.jwt.headers["kid"] == federation_kid:
                return ss

        return None


class RegistrationRequestVerification(object):
    """Client metadata attributes which are JSON arrays in registration request."""
    METADATA_AS_ARRAYS = [("response_types", "response_types_supported"),
                          ("grant_types", "grant_types_supported"),
                          ("default_acr_values", "acr_values_supported")]

    def verify(self, provider_capabilities, provider_software_statement, client_preferences,
               client_software_statement):
        # type: (Mapping[str, Union[str, Sequence[str]]],
        #        Mapping[str, Union[str, Sequence[str]]],
        #        Mapping[str, Union[str, Sequence[str]]],
        #        Mapping[str, Union[str, Sequence[str]]]) -> Dict[str, Union[str, List[str]]]
        """
        Verify the provider can satisfy the client's registration request.


        Negotiates the metadata parameters combined from the provider metadata, provider software
        statement, client metadata, and client software statement.

        :param provider_capabilities: provider metadata
        :param provider_software_statement: provider software statement
        :param client_preferences: client metadata
        :param client_software_statement: client software statement
        :raise OIDCFederationError: if the client metadata can't be matched with the provider's
                                    capabilities
        :return: the "negotiated" client metadata parameters that overrides/extends the initial
                 registration request
        """
        client_preferences = copy.deepcopy(client_preferences)
        client_preferences.update(client_software_statement)
        provider_capabilities = copy.deepcopy(provider_capabilities)
        provider_capabilities.update(provider_software_statement)

        client_preferences.update(
                self._match_array_preferences(client_preferences, provider_capabilities))

        for client_preference, provider_capability in [v for v in
                                                       PREFERENCE2PROVIDER.items() if
                                                       v not in RegistrationRequestVerification.METADATA_AS_ARRAYS]:
            if client_preference not in client_preferences and provider_capability in provider_software_statement:
                # default to metadata from provider software statement to ensure restrictions from
                # the federation are applied
                restrictions = provider_software_statement[provider_capability]
                # just select the first, but could be some smarter heuristic
                client_preferences[client_preference] = restrictions[0]
                continue

            try:
                client_value = client_preferences[client_preference]
                provider_values = provider_capabilities[provider_capability]
            except KeyError:
                continue

            if client_value not in provider_values:
                raise OIDCFederationError(
                        "Mismatch in registration request: {} '{}' not in {} '{}'.".format(
                                client_preference, client_value, provider_capability,
                                provider_values))

        return client_preferences

    def _match_array_preferences(self, client_preferences, provider_capabilities):
        # type: (Mapping[str, Union[str, Sequence[str]]],
        #        Mapping[str, Union[str, Sequence[str]]]) -> Dict[str, Union[str, List[str]]]
        """

        :param client_preferences: client metadata
        :param provider_capabilities: provider metadata
        :raise OIDCFederationError: if no common metadata parameters can be found
        :return: the negotiated/matching metadata
        """
        matching_preferences = {}
        if "response_types" in client_preferences:
            matching_preferences["response_types"] = self._match_response_types(
                    client_preferences["response_types"],
                    provider_capabilities["response_types_supported"])

        for client_preference, provider_capability in RegistrationRequestVerification.METADATA_AS_ARRAYS:
            if client_preference == "response_types":
                # skip as it's already been handled
                continue

            if client_preference in client_preferences:
                client_values = set(client_preferences[client_preference])
                provider_values = set(provider_capabilities[provider_capability])
                common_values = client_values & provider_values
                if not common_values:
                    raise OIDCFederationError(
                            "Mismatch in registration request, no common {} from client '{}' and provider {} '{}'.".format(
                                    client_preference, client_values, provider_capability,
                                    provider_values))

                matching_preferences[client_preference] = list(common_values)

        return matching_preferences

    def _match_response_types(self, client_response_types, provider_response_types):
        # type: (Sequence[str], Sequence[str]) -> List[str]
        """

        :param client_response_types: response types the client wants to register, where each
                                      response type is space-separated,
        :param provider_response_types: response types supported by the provider, where each
                                        response type is space-separated
        :return: the matching response types as space-separated strings
        """
        client_values = {frozenset(response_type.split(" ")) for response_type in
                         client_response_types}
        provider_values = {frozenset(response_type.split(" ")) for response_type in
                           provider_response_types}
        common_response_types = client_values & provider_values
        if not common_response_types:
            raise OIDCFederationError(
                    "Mismatch in registration request, no common response_types from client '{}' and provider response_types_supported '{}'.".format(
                            client_response_types, provider_response_types))

        return [" ".join(rt) for rt in common_response_types]
