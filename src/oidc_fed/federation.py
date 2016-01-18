import json

from jwkest.jwk import Key
from jwkest.jws import JWS


class Federation(object):
    def __init__(self, signing_key: Key, signing_alg: str, required_attributes: set = None,
                 policy: dict = None) -> None:
        """
        :param signing_key: key to use when signing software statements
        :param signing_alg: which algorithm to use when signing the software statements
        :param required_attributes: attribute names that must be present in the registration data
        :param policy: additional attributes that should be included in the signed software statement
        """
        self.signing_key = signing_key
        self.signing_alg = signing_alg
        self.required_attributes = required_attributes
        self.policy = policy

    def create_software_statement(self, registration_data: dict) -> str:
        """
        Issue a signed software statement.

        :param registration_data: information about the registering party
        :raise ValueError: if not all required attributes are present
        :return: signed software statement (as a JWS)
        """
        if self.required_attributes and not self.required_attributes.issubset(
                registration_data.keys()):
            raise ValueError("Missing required attributes {}.".format(
                    self.required_attributes - registration_data.keys()))

        software_statement = registration_data.copy()
        if self.policy:
            software_statement.update(self.policy)

        return JWS(json.dumps(software_statement), alg=self.signing_alg).sign_compact(
                keys=[self.signing_key])
