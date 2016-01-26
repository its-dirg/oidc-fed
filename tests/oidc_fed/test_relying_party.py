import json

import pytest
import responses
from Crypto.PublicKey import RSA
from jwkest.jwk import SYMKey, RSAKey
from jwkest.jws import JWS
from oic.extension.signed_http_req import SignedHttpRequest
from oic.oauth2 import rndstr

from oidc_fed import OIDCFederationError
from oidc_fed.federation import Federation
from oidc_fed.messages import (FederationProviderConfigurationResponse,
                               FederationRegistrationRequest,
                               FederationRegistrationResponse)
from oidc_fed.relying_party import RP

ISSUER = "https://op.example.com"
DEFAULT_PROVIDER_CONFIG = dict(issuer=ISSUER, subject_types_supported=["public"],
                               response_types_supported=["code"],
                               id_token_signing_alg_values_supported=["RS256"])


def rsa_key():
    return RSAKey(key=RSA.generate(1024), use="sig", alg="RS256", kid=rndstr(4))


def sym_key():
    return SYMKey(k=rndstr(), use="sig", alg="HS256", kid=rndstr(4))


class TestRP(object):
    @responses.activate
    def test_get_provider_configuration(self):
        # key/signing stuff
        federation_key = sym_key()
        op_root_key = rsa_key()
        op_registration_data = dict(root_key=json.dumps(op_root_key.serialize(private=False)))
        op_software_statement = Federation(federation_key).create_software_statement(
                op_registration_data)
        op_intermediary_key = rsa_key()

        # provider config
        provider_config = DEFAULT_PROVIDER_CONFIG.copy()
        provider_config["software_statements"] = [op_software_statement]
        provider_config["signing_key"] = JWS(op_intermediary_key.serialize(private=False),
                                             alg=op_root_key.alg).sign_compact(keys=[op_root_key])
        provider_config["signed_jwks_uri"] = "{}/signed_jwks".format(ISSUER)

        # signed metadata
        provider_config["id_token_signing_alg_values_supported"] = ["RS256"]
        signed_metadata = provider_config.copy()
        signed_metadata["id_token_signing_alg_values_supported"] = ["RS512"]
        provider_config["signed_metadata"] = JWS(json.dumps(signed_metadata),
                                                 alg=op_intermediary_key.alg).sign_compact(
                keys=[op_intermediary_key])

        # provider configuration endpoint
        responses.add(responses.GET, "{}/.well-known/openid-configuration".format(ISSUER),
                      body=json.dumps(provider_config), status=200,
                      content_type="application/json")

        rp = RP(None, [], [federation_key], None)
        provider_config = rp.get_provider_configuration(ISSUER)
        assert provider_config["issuer"] == ISSUER
        # value from signed metadata overrides plain value
        assert provider_config["id_token_signing_alg_values_supported"] == ["RS512"]

    def test_reject_provider_configuration_with_missing_parameter(self):
        rp = RP(None, [], None, None)
        with pytest.raises(OIDCFederationError) as exc:
            # default provider config missing all extra required attributes of FederationProviderConfigurationResponse
            rp._validate_provider_configuration(
                    FederationProviderConfigurationResponse(**DEFAULT_PROVIDER_CONFIG))

    def test_reject_signed_metadata_not_signed_by_provider_intermediary_key(self):
        op_intermediary_key = rsa_key()
        other_key = rsa_key()
        rp = RP(None, [], None, None)
        signed_provider_metadata = JWS(json.dumps(DEFAULT_PROVIDER_CONFIG),
                                       alg=other_key.alg).sign_compact(keys=[other_key])

        with pytest.raises(OIDCFederationError):
            rp._verify_signed_provider_metadata(signed_provider_metadata, op_intermediary_key)

    def test_accept_signed_metadata_provider_intermediary_key(self):
        op_intermediary_key = rsa_key()
        rp = RP(None, [], None, None)
        signed_provider_metadata = JWS(json.dumps(DEFAULT_PROVIDER_CONFIG),
                                       alg=op_intermediary_key.alg).sign_compact(
                keys=[op_intermediary_key])

        assert rp._verify_signed_provider_metadata(signed_provider_metadata, op_intermediary_key)

    def test_create_registration_request(self):
        signed_jwks_uri = "{}/signed_jwks".format(ISSUER)
        federation_key = sym_key()
        rp_root_key = rsa_key()
        rp_software_statement = Federation(federation_key).create_software_statement(
                dict(redirect_uris=["https://rp.example.com"]))
        rp = RP(rp_root_key, [rp_software_statement], [federation_key], signed_jwks_uri)

        reg_req = rp._create_registration_request({})
        assert reg_req.verify()
        assert reg_req["software_statements"] == [rp_software_statement]
        assert reg_req["signing_key"] == rp.signed_intermediary_key
        assert reg_req["signed_jwks_uri"] == signed_jwks_uri

    def test_sign_registration_request(self):
        rp_root_key = rsa_key()
        rp = RP(rp_root_key, [], None, None)

        reg_req = FederationRegistrationRequest(**{"foo": "bar"})
        signed = rp._sign_registration_request(reg_req)
        assert SignedHttpRequest(rp.intermediary_key).verify(signed, body=reg_req.to_json())

    @responses.activate
    def test_handle_registration_response(self):
        federation_key = sym_key()
        op_root_key = rsa_key()
        op_intermediary_key = rsa_key()
        op_signed_intermediary_key = JWS(json.dumps(op_intermediary_key.serialize(private=False)),
                                         alg=op_root_key.alg).sign_compact(keys=[op_root_key])
        op_software_statement = Federation(federation_key).create_software_statement(
                dict(root_key=json.dumps(op_root_key.serialize(private=False)),
                     scopes_supported=["openid", "test_scope"]))
        rp = RP(None, [], [federation_key], None)

        signed_jwks_uri = "{}/signed_jwks".format(ISSUER)
        # fake provider discovery
        rp.client.provider_info = FederationProviderConfigurationResponse(
                **dict(signing_key=op_signed_intermediary_key, signed_jwks_uri=signed_jwks_uri,
                       issuer=ISSUER))
        # signed_jwks_uri
        expected_kid = "OP key 1"
        keys = [RSAKey(key=RSA.generate(1024), kid=expected_kid).serialize(private=False)]
        jwks = json.dumps(dict(keys=keys))
        jws = JWS(jwks, alg=op_intermediary_key.alg).sign_compact(keys=[op_intermediary_key])
        responses.add(responses.GET, signed_jwks_uri, body=jws, status=200,
                      content_type="application/jose")

        resp_args = dict(provider_software_statement=op_software_statement, client_id="foo")
        reg_resp = FederationRegistrationResponse(**resp_args)

        rp._handle_registration_response(reg_resp)
        assert set(rp.client.provider_info["scopes_supported"]) == {"openid", "test_scope"}
        assert rp.client.client_id == "foo"
        assert rp.client.keyjar[ISSUER][0].keys()[0].kid == expected_kid

    def test_handle_registration_response_fail_when_wrong_software_statement(self):
        rp = RP(None, [], None, None)
        rp.client.provider_info = FederationProviderConfigurationResponse(
                **dict(signing_key="whatever"))  # fake provider discovery

        resp_args = dict(provider_software_statement="abcdef")
        reg_resp = FederationRegistrationResponse(**resp_args)

        with pytest.raises(OIDCFederationError) as exc:
            rp._handle_registration_response(reg_resp)

        assert "software statement" in str(exc.value)

    @responses.activate
    def test_register_with_provider(self):
        registration_endpoint = "{}/registration".format(ISSUER)
        signed_jwks_uri = "{}/signed_jwks".format(ISSUER)
        federation_key = sym_key()
        rp_root_key = rsa_key()
        rp_software_statement = Federation(federation_key).create_software_statement(
                dict(redirect_uris=["https://rp.example.com"]))

        op_root_key = rsa_key()
        op_intermediary_key = rsa_key()
        op_signed_intermediary_key = JWS(json.dumps(op_intermediary_key.serialize(private=False)),
                                         alg=op_root_key.alg).sign_compact(keys=[op_root_key])
        op_software_statement = Federation(federation_key).create_software_statement(
                dict(root_key=json.dumps(op_root_key.serialize(private=False)),
                     scopes_supported=["openid", "test_scope"]))

        # signed_jwks_uri
        expected_kid = "OP key 1"
        keys = [RSAKey(key=RSA.generate(1024), kid=expected_kid).serialize(private=False)]
        jwks = json.dumps(dict(keys=keys))
        jws = JWS(jwks, alg=op_intermediary_key.alg).sign_compact(keys=[op_intermediary_key])
        responses.add(responses.GET, signed_jwks_uri, body=jws, status=200,
                      content_type="application/jose")

        rp = RP(rp_root_key, [rp_software_statement], [federation_key], None)
        rp.client.provider_info = FederationProviderConfigurationResponse(
                **dict(issuer=ISSUER, signing_key=op_signed_intermediary_key,
                       registration_endpoint=registration_endpoint,
                       signed_jwks_uri=signed_jwks_uri))

        reg_resp = FederationRegistrationResponse(
                **dict(provider_software_statement=op_software_statement,
                       client_id="foo", redirect_uris=["https://rp.example.com"]))
        responses.add(responses.POST, registration_endpoint, body=reg_resp.to_json(), status=201,
                      content_type="application/json")

        client_registration_data = {}
        rp.register_with_provider(ISSUER, client_registration_data)
        assert rp.client.client_id == "foo"
        assert rp.client.provider_signing_key == op_intermediary_key
        assert rp.client.keyjar[ISSUER][0].keys()[0].kid == expected_kid
