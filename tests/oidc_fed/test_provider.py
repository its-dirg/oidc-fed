import json

from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey, SYMKey
from jwkest.jws import JWS
from oic.oauth2 import rndstr

from oidc_fed.federation import Federation
from oidc_fed.provider import OP


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
