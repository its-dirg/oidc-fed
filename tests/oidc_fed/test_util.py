import json

import pytest
import requests
import responses
from Crypto.PublicKey import RSA
from jwkest.jwk import RSAKey
from jwkest.jws import JWS
from oic.utils.keyio import UpdateFailed

from oidc_fed.util import SignedKeyBundle, KeyJarWithSignedKeyBundles


def create_jwks(kid=""):
    keys = [RSAKey(key=RSA.generate(1024), kid=kid).serialize(private=False)]
    jwks = json.dumps(dict(keys=keys))
    return jwks


def create_signed_jwks(signing_key, jwks_key_kid=""):
    jwks = create_jwks(jwks_key_kid)
    return JWS(jwks, alg=signing_key.alg).sign_compact(keys=[signing_key])


class TestSignedJWKS(object):
    @responses.activate
    def test_do_remote(self):
        expected_kid = "test key"
        url = "https://example.com/signed_jwks"
        signing_key = RSAKey(key=RSA.generate(1024), alg="RS256")
        jws = create_signed_jwks(signing_key, expected_kid)
        responses.add(responses.GET, url, body=jws, status=200, content_type="application/jose")

        kb = SignedKeyBundle(verification_key=signing_key, source=url)
        assert kb.do_remote()
        assert kb.keys()[0].kid == expected_kid

    @responses.activate
    def test_do_remote_reject_jwks_signed_with_unknown_key(self):
        url = "https://example.com/signed_jwks"
        signing_key = RSAKey(key=RSA.generate(1024), alg="RS256")
        other_key = RSAKey(key=RSA.generate(1024), alg="RS256")

        jws = create_signed_jwks(signing_key)
        responses.add(responses.GET, url, body=jws, status=200, content_type="application/jose")

        kb = SignedKeyBundle(verification_key=other_key, source=url)
        with pytest.raises(UpdateFailed) as exc:
            kb.do_remote()

        assert "signature" in str(exc.value)

    @responses.activate
    def test_do_remote_handle_wrong_content_type(self):
        expected_kid = "test key"
        url = "https://example.com/signed_jwks"
        signing_key = RSAKey(key=RSA.generate(1024), alg="RS256")

        jws = create_signed_jwks(signing_key, expected_kid)
        responses.add(responses.GET, url, body=jws, status=200, content_type="application/json")

        kb = SignedKeyBundle(verification_key=signing_key, source=url)
        kb.do_remote()
        assert kb.keys()[0].kid == expected_kid

    @responses.activate
    def test_do_remote_handles_connection_error(self):
        url = "https://example.com/signed_jwks"
        responses.add(responses.GET, url, body=requests.ConnectionError("Error"))
        kb = SignedKeyBundle(verification_key=None, source=url)
        with pytest.raises(UpdateFailed) as exc:
            kb.do_remote()

    @responses.activate
    def test_do_remote_reject_malformed_jwks(self):
        url = "https://example.com/signed_jwks"

        signing_key = RSAKey(key=RSA.generate(1024), alg="RS256")
        jws = JWS("foobar", alg=signing_key.alg).sign_compact(keys=[signing_key])
        responses.add(responses.GET, url, body=jws, status=200, content_type="application/jose")

        kb = SignedKeyBundle(verification_key=signing_key, source=url)
        with pytest.raises(UpdateFailed) as exc:
            kb.do_remote()

        assert "malformed" in str(exc.value)


class TestKeyJarWithSignedKeyBundles(object):
    @responses.activate
    def test_load_keys(self):
        expected_kid = "test key"
        issuer = "https://op.example.com"
        url = "{}/signed_jwks".format(issuer)
        signing_key = RSAKey(key=RSA.generate(1024), alg="RS256")

        jws = create_signed_jwks(signing_key, expected_kid)
        responses.add(responses.GET, url, body=jws, status=200, content_type="application/jose")

        keyjar = KeyJarWithSignedKeyBundles()
        keyjar.load_keys(url, issuer, signing_key)

        assert keyjar[issuer][0].keys()[0].kid == expected_kid

    @responses.activate
    def test_load_keys_failed_fetching_jwks(self):
        url = "https://op.example.com/signed_jwks"
        responses.add(responses.GET, url, body=requests.ConnectionError("Error"))

        keyjar = KeyJarWithSignedKeyBundles()
        with pytest.raises(ValueError):
            keyjar.load_keys(url, "", None)
