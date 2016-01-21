import logging

from jwkest import JWKESTException
from jwkest.jws import JWS
from oic.oic import Client
from oic.utils.keyio import KeyBundle, UpdateFailed, KeyJar

logger = logging.getLogger(__name__)


class KeyJarWithSignedKeyBundles(KeyJar):
    def __init__(self):
        # type: () -> None
        super(KeyJarWithSignedKeyBundles, self).__init__(keybundle_cls=SignedKeyBundle)

    def load_keys(self, url, issuer, verification_key):
        # type (str, str, Key) -> None
        """
        Fetch a signed JWKS from an URL and verify its signature.

        :param url: url to fetch JWKS from
        :param issuer: owner of the JWKS
        :param verification_key: key to use to verify the signature of the signed JWKS
        :raise ValueError: if the JWKS could not be fetched or verified
        """
        super(KeyJarWithSignedKeyBundles, self).load_keys({}, issuer)

        kb = self.add(issuer, url, verification_key=verification_key)
        # force update
        try:
            kb.do_remote()
        except UpdateFailed as e:
            raise ValueError("Could not fetch keys from 'signed_jwks_uri': {}".format(str(e)))


class SignedKeyBundle(KeyBundle):
    def __init__(self, verification_key, **kwargs):
        # type: (Key, **Any) -> None
        self.verification_key = verification_key
        super(SignedKeyBundle, self).__init__(**kwargs)

    def _parse_remote_response(self, response):
        # type: (requests.Response) -> Dict[str, Dict[str, List[Dict[str, str]]]
        """
        Parse the response from the fetched remote URL.

        :param response: response to parse
        :raise UpdateFailed: if the signature of the JWKS could not be verified
        :return: parsed JWKS
        """
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


class FederationClient(Client):
    def __init__(self, *args, **kwargs):
        super(FederationClient, self).__init__(*args, **kwargs)

        self.provider_signing_key = None  # type: Key
        self.keyjar = KeyJarWithSignedKeyBundles()
