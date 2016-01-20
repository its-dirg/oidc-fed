import logging

from jwkest import JWKESTException
from jwkest.jws import JWS
from oic.utils.keyio import KeyBundle, UpdateFailed, KeyJar

logger = logging.getLogger(__name__)


class KeyJarWithSignedKeyBundles(KeyJar):
    def __init__(self, ca_certs=None, verify_ssl=True):
        super(KeyJarWithSignedKeyBundles, self).__init__(ca_certs=ca_certs, verify_ssl=verify_ssl, keybundle_cls=SignedKeyBundle)

    def load_keys(self, pcr, issuer, verification_key, replace=False):
        super(KeyJarWithSignedKeyBundles, self).load_keys(pcr, issuer)

        try:
            url = pcr["signed_jwks_uri"]
        except KeyError:
            raise ValueError("Provider configuration MUST contain 'signed_jwks_uri'.")

        kb = self.add(issuer, url, verification_key=verification_key)
        # force update
        try:
            kb.do_remote()
        except UpdateFailed as e:
            raise ValueError("Could not fetch keys from 'signed_jwks_uri': {}".format(str(e)))


class SignedKeyBundle(KeyBundle):
    def __init__(self, verification_key, **kwargs):
        self.verification_key = verification_key
        super(SignedKeyBundle, self).__init__(**kwargs)

    def _parse_remote_response(self, response):
        # only handle 'application/jose' (signed compact JWS)
        if "Content-Type" not in response.headers or response.headers[
            "Content-Type"] != 'application/jose':
            logger.debug(
                "JWKS response from '{}' has wrong or missing Content-Type.".format(response.url))
        try:
            return JWS().verify_compact(response.text, keys=[self.verification_key])
        except JWKESTException as e:
            raise UpdateFailed(
                    "Remote key update from '{}' failed, could not verify signature.".format(
                            self.source))
