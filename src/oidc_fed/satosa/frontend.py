import logging

from jwkest.jwk import keyrep
from oic.utils.http_util import Response, Created, get_post
from satosa.frontends.oidc import OIDCFrontend
from satosa.logging_util import satosa_logging

from oidc_fed import OIDCFederationError
from ..provider import OP

LOGGER = logging.getLogger(__name__)


class OIDCFederationFrontend(OIDCFrontend):
    MANDATORY_CONFIG = OIDCFrontend.MANDATORY_CONFIG | {"root_key_jwk", "software_statements",
                                                        "federations_jwk"}

    def __init__(self, auth_req_callback_func, internal_attributes, conf):
        super().__init__(auth_req_callback_func, internal_attributes, conf)

        self.root_key = keyrep(conf["root_key_jwk"])
        self.software_statements = conf["software_statements"]
        self.federation_keys = []
        for k in conf["federations_jwk"]:
            self.federation_keys.append(keyrep(k))

    def register_endpoints(self, providers):
        url_map = super().register_endpoints(providers)
        self.OP = OP(self.provider.name, self.root_key, self.software_statements,
                     self.federation_keys, self.provider.name + "/signed_jwks", self.provider,
                     self.provider.name + "/jwks")

        signed_jwks = ("^signed_jwks$", self._signed_jwks)
        url_map.append(signed_jwks)
        return url_map

    def _signed_jwks(self, context):
        return Response(self.OP.signed_jwks, content="application/jose")

    def _provider_config(self, context):
        return self.OP.provider_configuration()

    def _register_client(self, context):
        http_authz = context.wsgi_environ.get("HTTP_AUTHORIZATION")
        try:
            post_body = get_post(context.wsgi_environ)
            http_resp = self.OP.register_client(http_authz, post_body)
        except OIDCFederationError as e:
            satosa_logging(LOGGER, logging.ERROR,
                           "OIDCFederation frontend error: {}".format(str(e)), context.state)
            return Response(str(e))

        if not isinstance(http_resp, Created):
            return http_resp

        return self._fixup_registration_response(http_resp)
