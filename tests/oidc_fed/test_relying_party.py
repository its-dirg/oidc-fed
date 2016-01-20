import json

import pytest
import responses
from Crypto.PublicKey import RSA
from jwkest.jwk import SYMKey, RSAKey
from jwkest.jws import JWS
from oic.oauth2 import rndstr

from oidc_fed import OIDCFederationError
from oidc_fed.federation import Federation
from oidc_fed.messages import FederationProviderConfigurationResponse
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
    def test_key_init(self):
        rp = RP(sym_key(), None, None)

        assert JWS().verify_compact(rp.signed_intermediary_key, keys=[rp.root_key])
        assert JWS().verify_compact(rp.signed_jwks, keys=[rp.intermediary_key])

    def test_key_rotation(self):
        rp = RP(sym_key(), None, None)

        rp.rotate_intermediary_key()
        rp.rotate_jwks()
        assert JWS().verify_compact(rp.signed_intermediary_key, keys=[rp.root_key])
        assert JWS().verify_compact(rp.signed_jwks, keys=[rp.intermediary_key])

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

        # signed JWKS
        signed_jwks_uri = "{}/signed_jwks".format(ISSUER)
        provider_config["signed_jwks_uri"] = signed_jwks_uri

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
        # signed_jwks_uri
        expected_kid = "OP key 1"
        keys = [RSAKey(key=RSA.generate(1024), kid=expected_kid).serialize(private=False)]
        jwks = json.dumps(dict(keys=keys))
        jws = JWS(jwks, alg=op_intermediary_key.alg).sign_compact(keys=[op_intermediary_key])
        responses.add(responses.GET, signed_jwks_uri, body=jws, status=200,
                      content_type="application/jose")

        rp = RP(None, None, federation_keys=[federation_key])
        provider_config = rp.get_provider_configuration(ISSUER)
        assert provider_config["issuer"] == ISSUER
        # value from signed metadata overrides plain value
        assert provider_config["id_token_signing_alg_values_supported"] == ["RS512"]
        # the signed JWKS could be fetched and verified
        assert rp.client.keyjar[ISSUER][0].keys()[0].kid == expected_kid

    def test_reject_provider_configuration_with_missing_parameter(self):
        rp = RP(None, None, None)
        with pytest.raises(OIDCFederationError) as exc:
            # default provider config missing all extra required attributes of FederationProviderConfigurationResponse
            rp._validate_provider_configuration(
                    FederationProviderConfigurationResponse(**DEFAULT_PROVIDER_CONFIG))

    def test_reject_provider_with_no_common_federation(self):
        fed1_key = SYMKey(k="one_key", alg="HS256", use="sig")
        federation1 = Federation(fed1_key)
        federation2 = Federation(SYMKey(k="other_key1", alg="HS256", use="sig"))
        rp_software_statement = federation1.create_software_statement({"foo": "bar"})
        op_software_statement = federation2.create_software_statement({"abc": "xyz"})

        rp = RP(None, software_statements=[rp_software_statement], federation_keys=[fed1_key])
        with pytest.raises(OIDCFederationError):
            rp._verify_software_statements([op_software_statement])

    def test_accept_provider_with_common_federation(self):
        fed1_key = SYMKey(k="one_key", alg="HS256", use="sig")
        federation = Federation(fed1_key)
        rp_software_statement = federation.create_software_statement({"foo": "bar"})
        op_software_statement = federation.create_software_statement({"abc": "xyz"})

        rp = RP(None, software_statements=[rp_software_statement], federation_keys=[fed1_key])
        assert rp._verify_software_statements([op_software_statement])

    def test_reject_provider_signing_key_not_signed_by_software_statement_root_key(self):
        op_root_key = rsa_key()
        op_intermediary_key = rsa_key()

        # sign intermediary key with key other than op_root_key
        other_key = rsa_key()
        op_signing_key = JWS(op_intermediary_key.serialize(private=False),
                             alg=other_key.alg).sign_compact(keys=[other_key])

        rp = RP(None, None, None)
        with pytest.raises(OIDCFederationError):
            rp._verify_provider_signing_key(op_signing_key, op_root_key)

    def test_accept_provider_signing_key_signed_by_software_statement_root_key(self):
        op_root_key = rsa_key()
        op_intermediary_key = rsa_key()

        op_signing_key = JWS(op_intermediary_key.serialize(private=False),
                             alg=op_root_key.alg).sign_compact(keys=[op_root_key])

        rp = RP(None, None, None)
        assert rp._verify_provider_signing_key(op_signing_key, op_root_key)

    def test_reject_signed_metadata_not_signed_by_provider_intermediary_key(self):
        op_intermediary_key = rsa_key()
        other_key = rsa_key()
        rp = RP(None, None, None)
        signed_provider_metadata = JWS(json.dumps(DEFAULT_PROVIDER_CONFIG),
                                       alg=other_key.alg).sign_compact(keys=[other_key])

        with pytest.raises(OIDCFederationError):
            rp._verify_signed_provider_metadata(signed_provider_metadata, op_intermediary_key)

    def test_accept_signed_metadata_provider_intermediary_key(self):
        op_intermediary_key = rsa_key()
        rp = RP(None, None, None)
        signed_provider_metadata = JWS(json.dumps(DEFAULT_PROVIDER_CONFIG),
                                       alg=op_intermediary_key.alg).sign_compact(
                keys=[op_intermediary_key])

        assert rp._verify_signed_provider_metadata(signed_provider_metadata, op_intermediary_key)
