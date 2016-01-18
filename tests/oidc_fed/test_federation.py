import pytest
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from oidc_fed.federation import Federation


class TestFederation(object):
    @pytest.fixture(autouse=True)
    def create_signing_key(self):
        self.signing_key = SYMKey(key="abcdef", use="sig")

    def test_create_software_statement(self):
        registration_data = {
            "foo": "bar"
        }
        federation = Federation(self.signing_key, "HS256")

        jws = federation.create_software_statement(registration_data)
        software_statement = JWS().verify_compact(jws, keys=[self.signing_key])

        assert all(item in software_statement.items() for item in registration_data.items())

    def test_create_software_statement_with_policy(self):
        registration_data = {
            "foo": "bar"
        }
        policy_attributes = {"abc": "xyz"}
        federation = Federation(self.signing_key, "HS256", policy=policy_attributes)

        jws = federation.create_software_statement(registration_data)
        software_statement = JWS().verify_compact(jws, keys=[self.signing_key])

        assert all(item in software_statement.items() for item in
                   (registration_data.items() | policy_attributes.items()))

    def test_create_software_statement_reject_registration_with_missing_data(self):
        registration_data = {
            "foo": "bar"
        }
        required_attributes = {"xyz", "bar"}
        federation = Federation(self.signing_key, "HS256", required_attributes=required_attributes)

        with pytest.raises(ValueError) as exc:
            federation.create_software_statement(registration_data)
