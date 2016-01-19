from oic.oauth2.message import REQUIRED_LIST_OF_STRINGS, SINGLE_REQUIRED_STRING
from oic.oic.message import ProviderConfigurationResponse


class FederationProviderConfigurationResponse(ProviderConfigurationResponse):
    c_param = ProviderConfigurationResponse.c_param.copy()
    c_param.update({"software_statements": REQUIRED_LIST_OF_STRINGS,
                    "signed_metadata": SINGLE_REQUIRED_STRING,
                    "signed_jwks_uri": SINGLE_REQUIRED_STRING,
                    "signing_key": SINGLE_REQUIRED_STRING})
