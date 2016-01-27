import json

from jwkest.jws import JWS

from . import verify_signing_key


class Federation(object):
    def __init__(self, signing_key, required_attributes=None, policy=None):
        # type: (Key, AbstractSet[str], Mapping[str, str]) -> None
        """
        :param signing_key: key to use when signing software statements
        :param required_attributes: attribute names that must be present in the registration data
        :param policy: additional attributes that should be included in the signed software statement
        :raise ValueError: if the specified signing missing 'alg' or does not have 'use=sig'
        """

        verify_signing_key(signing_key)

        self.signing_key = signing_key
        self.required_attributes = required_attributes
        self.policy = policy

    def create_software_statement(self, registration_data):
        # type: (Mapping[str, Union[str, Sequence[str]]) -> str
        """
        Issue a signed software statement.

        :param registration_data: information about the registering party
        :raise ValueError: if not all required attributes are present
        :return: signed software statement (as a JWS)
        """
        if self.required_attributes and not self.required_attributes.issubset(
                registration_data.keys()):
            raise ValueError("Missing required attributes {}.".format(
                    self.required_attributes - set(registration_data.keys())))

        software_statement = registration_data.copy()
        if self.policy:
            software_statement.update(self.policy)

        return JWS(json.dumps(software_statement), alg=self.signing_key.alg).sign_compact(
                keys=[self.signing_key])
