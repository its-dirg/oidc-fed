from oic.oauth2.message import (REQUIRED_LIST_OF_STRINGS, SINGLE_REQUIRED_STRING,
                                OPTIONAL_LIST_OF_STRINGS)
from oic.oic.message import ProviderConfigurationResponse, RegistrationRequest, RegistrationResponse

COMMON_FEDERATION_PARAMETERS = {
    "software_statements": REQUIRED_LIST_OF_STRINGS,
    "signed_jwks_uri": SINGLE_REQUIRED_STRING,
    "signing_key": SINGLE_REQUIRED_STRING
}


class FederationProviderConfigurationResponse(ProviderConfigurationResponse):
    c_param = ProviderConfigurationResponse.c_param.copy()
    c_param.update(COMMON_FEDERATION_PARAMETERS)
    c_param["signed_metadata"] = SINGLE_REQUIRED_STRING


class FederationRegistrationRequest(RegistrationRequest):
    c_param = RegistrationRequest.c_param.copy()
    c_param.update(COMMON_FEDERATION_PARAMETERS)
    # don't enforce redirect_uris, might be in software statement
    c_param["redirect_uris"] = OPTIONAL_LIST_OF_STRINGS


class FederationRegistrationResponse(RegistrationResponse):
    c_param = RegistrationResponse.c_param.copy()
    c_param["provider_software_statement"] = SINGLE_REQUIRED_STRING
