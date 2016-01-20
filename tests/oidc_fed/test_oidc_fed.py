from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from oic.oauth2 import rndstr

from oidc_fed import OIDCFederationEntity


def sym_key():
    return SYMKey(k=rndstr(), use="sig", alg="HS256", kid=rndstr(4))


class TestOIDCFederationEntity(object):
    def test_key_init(self):
        rp = OIDCFederationEntity(sym_key(), None, None, None)

        assert JWS().verify_compact(rp.signed_intermediary_key, keys=[rp.root_key])
        assert JWS().verify_compact(rp.signed_jwks, keys=[rp.intermediary_key])

    def test_key_rotation(self):
        rp = OIDCFederationEntity(sym_key(), None, None, None)

        rp.rotate_intermediary_key()
        rp.rotate_jwks()
        assert JWS().verify_compact(rp.signed_intermediary_key, keys=[rp.root_key])
        assert JWS().verify_compact(rp.signed_jwks, keys=[rp.intermediary_key])
