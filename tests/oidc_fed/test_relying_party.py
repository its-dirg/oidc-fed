from jwkest.jwk import SYMKey
from jwkest.jws import JWS

from oidc_fed.relying_party import RP


class TestRP(object):
    def test_key_init(self):
        root_key = SYMKey(k="abcdef", use="sig", alg="HS256")
        rp = RP(root_key)

        assert JWS().verify_compact(rp.signed_intermediary_key, keys=[rp.root_key])
        assert JWS().verify_compact(rp.signed_jwks, keys=[rp.intermediary_key])

    def test_key_rotation(self):
        root_key = SYMKey(k="abcdef", use="sig", alg="HS256")
        rp = RP(root_key)

        rp.rotate_intermediary_key()
        rp.rotate_jwks()
        assert JWS().verify_compact(rp.signed_intermediary_key, keys=[rp.root_key])
        assert JWS().verify_compact(rp.signed_jwks, keys=[rp.intermediary_key])
