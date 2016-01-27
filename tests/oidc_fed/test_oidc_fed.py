import pytest
from Crypto.PublicKey import RSA
from jwkest.jwk import SYMKey, RSAKey
from jwkest.jws import JWS
from oic.oauth2 import rndstr

from oidc_fed import OIDCFederationEntity, OIDCFederationError
from oidc_fed.federation import Federation


def rsa_key():
    return RSAKey(key=RSA.generate(1024), use="sig", alg="RS256", kid=rndstr(4))


def sym_key():
    return SYMKey(k=rndstr(), use="sig", alg="HS256", kid=rndstr(4))


class TestOIDCFederationEntity(object):
    def test_key_init(self):
        entity = OIDCFederationEntity(sym_key(), [], None, None)

        assert JWS().verify_compact(entity.signed_intermediate_key, keys=[entity.root_key])
        assert JWS().verify_compact(entity.signed_jwks, keys=[entity.intermediate_key])

    def test_key_rotation(self):
        entity = OIDCFederationEntity(sym_key(), [], None, None)

        entity.rotate_intermediate_key()
        entity.rotate_jwks()
        assert JWS().verify_compact(entity.signed_intermediate_key, keys=[entity.root_key])
        assert JWS().verify_compact(entity.signed_jwks, keys=[entity.intermediate_key])

    def test_accept_provider_signing_key_signed_by_software_statement_root_key(self):
        root_key = rsa_key()
        op_intermediate_key = rsa_key()
        entity = OIDCFederationEntity(sym_key(), [], None, None)

        signing_key = JWS(op_intermediate_key.serialize(private=False),
                          alg=root_key.alg).sign_compact(keys=[root_key])

        assert entity._verify_signing_key(signing_key, root_key)

    def test_reject_entity_with_no_common_federation(self):
        fed1_key = SYMKey(k="one_key", alg="HS256", use="sig")
        federation1 = Federation(fed1_key)
        federation2 = Federation(SYMKey(k="other_key1", alg="HS256", use="sig"))
        rp_software_statement = federation1.create_software_statement({"foo": "bar"})
        op_software_statement = federation2.create_software_statement({"abc": "xyz"})

        entity = OIDCFederationEntity(sym_key(), [rp_software_statement], [fed1_key], None)
        with pytest.raises(OIDCFederationError):
            entity._verify_software_statements([op_software_statement])

    def test_accept_entity_with_common_federation(self):
        fed1_key = SYMKey(k="one_key", alg="HS256", use="sig")
        federation = Federation(fed1_key)
        rp_software_statement = federation.create_software_statement({"foo": "bar"})
        op_software_statement = federation.create_software_statement({"abc": "xyz"})

        entity = OIDCFederationEntity(sym_key(), [rp_software_statement], [fed1_key], None)
        assert entity._verify_software_statements([op_software_statement])

    def test_reject_entity_signing_key_not_signed_by_software_statement_root_key(self):
        root_key = rsa_key()
        intermediate_key = rsa_key()

        # sign intermediate key with key other than op_root_key
        other_key = rsa_key()
        signing_key = JWS(intermediate_key.serialize(private=False),
                          alg=other_key.alg).sign_compact(keys=[other_key])

        entity = OIDCFederationEntity(sym_key(), [], None, None)
        with pytest.raises(OIDCFederationError):
            entity._verify_signing_key(signing_key, root_key)

    def test_reject_root_key_without_kid(self):
        signing_key = SYMKey()
        with pytest.raises(OIDCFederationError) as exc:
            OIDCFederationEntity(signing_key, [], None, None)

        assert "kid" in str(exc.value)
