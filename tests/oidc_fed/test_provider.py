import json
from collections import Counter

import pytest
from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey, SYMKey
from jwkest.jws import JWS
from oic.extension.signed_http_req import SignedHttpRequest
from oic.oauth2 import rndstr

from oidc_fed import OIDCFederationError
from oidc_fed.federation import Federation
from oidc_fed.messages import FederationRegistrationRequest, FederationRegistrationResponse
from oidc_fed.provider import OP, RegistrationRequestVerification


def rsa_key():
    return RSAKey(key=RSA.generate(1024), use="sig", alg="RS256", kid=rndstr(4))


def sym_key():
    return SYMKey(k=rndstr(), use="sig", alg="HS256", kid=rndstr(4))


class TestOP(object):
    def test_provider_configuration(self):
        issuer = "https://op.example.com"
        signed_jwks_uri = "{}/signed_jwks".format(issuer)
        federation_key = sym_key()
        op_root_key = rsa_key()
        op_registration_data = dict(root_key=json.dumps(op_root_key.serialize(private=False)))
        op_software_statement = Federation(federation_key).create_software_statement(
                op_registration_data)

        op = OP(issuer, op_root_key, [op_software_statement], [federation_key], signed_jwks_uri)

        provider_config = op.provider_configuration()
        assert provider_config["issuer"] == issuer
        assert provider_config["software_statements"] == [op_software_statement]
        assert provider_config["signing_key"] == op.signed_intermediary_key
        assert provider_config["signed_jwks_uri"] == signed_jwks_uri

        expected_metadata_parameters = set(provider_config.keys())
        expected_metadata_parameters.remove("signed_metadata")
        actual_metadata_parameters = JWS().verify_compact(provider_config["signed_metadata"],
                                                          keys=[op.intermediary_key]).keys()
        assert set(actual_metadata_parameters) == expected_metadata_parameters

    def test_register_client(self):
        federation_key = sym_key()
        federation = Federation(federation_key)

        op_root_key = rsa_key()
        op_software_statement = federation.create_software_statement(
                dict(root_key=json.dumps(op_root_key.serialize(private=False)),
                     response_types_supported=["code"]))
        op = OP(None, None, [op_software_statement], [federation_key], None)

        rp_root_key = rsa_key()
        rp_intermediary_key = rsa_key()
        rp_signed_intermediary_key = JWS(json.dumps(rp_intermediary_key.serialize(private=False)),
                                         alg=rp_root_key.alg).sign_compact(keys=[rp_root_key])
        rp_software_statement = federation.create_software_statement(
                dict(root_key=json.dumps(rp_root_key.serialize(private=False)),
                     response_types=["code"]))
        client_metadata = {
            "signing_key": rp_signed_intermediary_key,
            "signed_jwks_uri": "https://rp.example.com/signed_jwks",
            "software_statements": [rp_software_statement],
            "redirect_uris": ["https://rp.example.com"],
            "response_types": ["id_token"]
        }
        req = FederationRegistrationRequest(**client_metadata)
        signature = SignedHttpRequest(rp_intermediary_key).sign(rp_intermediary_key.alg,
                                                                body=req.to_json())

        client_metadata = op.register_client({"Authorization": "pop {}".format(signature)},
                                      req.to_json())
        registration_response = FederationRegistrationResponse().from_dict(client_metadata)
        assert registration_response.verify()
        assert "client_id" in registration_response
        assert registration_response["provider_software_statement"] == op_software_statement
        assert registration_response["response_types"] == ["code"]

    def test_register_client_reject_request_without_authorization(self):
        with pytest.raises(OIDCFederationError) as exc:
            OP(None, None, [], None, None).register_client({}, None)

        assert "Authorization" in str(exc.value)

    def test_register_client_rejects_request_with_wrong_auth_scheme(self):
        with pytest.raises(OIDCFederationError) as exc:
            OP(None, None, [], None, None).register_client({"Authorization": "Basic foobar"},
                                                           None)

        assert "Authentication scheme" in str(exc.value)


class TestRegistrationRequestVerification(object):
    def test_verify(self):
        provider_capabilities = {"id_token_signing_alg_values_supported": ["RS256", "RS512"],
                                 "request_object_signing_alg_values_supported": ["RS256"]}
        client_preferences = {"id_token_signed_response_alg": "RS512",
                              "userinfo_signed_response_alg": "RS512"}

        verifier = RegistrationRequestVerification()
        matched_prefs = verifier.verify(provider_capabilities, {}, client_preferences, {})
        assert matched_prefs == client_preferences

    def test_verify_rejects_conflicting_request(self):
        provider_capabilities = {"id_token_signing_alg_values_supported": ["RS256"]}
        client_preferences = {"id_token_signed_response_alg": "RS512"}

        with pytest.raises(OIDCFederationError):
            RegistrationRequestVerification().verify(provider_capabilities, {}, client_preferences,
                                                     {})

    def test_provider_software_statement_overrides(self):
        provider_capabilities = {
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        provider_software_statement = {"id_token_signing_alg_values_supported": ["RS512"]}

        client_preferences = {"id_token_signed_response_alg": "RS512"}

        matched_prefs = RegistrationRequestVerification().verify(provider_capabilities,
                                                                 provider_software_statement,
                                                                 client_preferences, {})
        assert matched_prefs == client_preferences

    def test_client_software_statement_overrides(self):
        provider_capabilities = {
            "id_token_signing_alg_values_supported": ["RS256", "RS512"],
        }

        client_preferences = {"id_token_signed_response_alg": "RS256"}
        client_software_statement = {"id_token_signed_response_alg": "RS512"}

        matched_prefs = RegistrationRequestVerification().verify(provider_capabilities, {},
                                                                 client_preferences,
                                                                 client_software_statement)
        assert matched_prefs == client_software_statement

    def test_provider_software_statement_is_default(self):
        provider_capabilities = {
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        provider_software_statement = {"id_token_signing_alg_values_supported": ["RS512"]}

        matched_prefs = RegistrationRequestVerification().verify(provider_capabilities,
                                                                 provider_software_statement,
                                                                 {}, {})
        assert matched_prefs == {"id_token_signed_response_alg": "RS512"}

    def test_client_preferences_as_arrays_are_matched(self):
        client_preferences = {
            "response_types": ["code", "token id_token"],
            "grant_types": ["authorization_code", "implicit"],
            "default_acr_values": ["u2f", "password"]
        }
        provider_capabilities = {
            "response_types_supported": ["code", "code id_token token", "id_token token"],
            "grant_types_supported": ["authorization_code"],
            "acr_values_supported": ["uaf", "u2f"]
        }

        matched_prefs = RegistrationRequestVerification().verify(provider_capabilities, {},
                                                                 client_preferences, {})

        assert {frozenset(response_type.split(" ")) for response_type in
                matched_prefs["response_types"]} == \
               {frozenset(response_type.split(" ")) for response_type in
                ["code", "token id_token"]}
        assert matched_prefs["grant_types"] == ["authorization_code"]
        assert matched_prefs["default_acr_values"] == ["u2f"]
