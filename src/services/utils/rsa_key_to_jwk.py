#! /usr/bin/env python3

from argparse import ArgumentParser

from jwkest.jwk import RSAKey, import_rsa_key_from_file
from oic.oauth2 import rndstr

from oidc_fed.util import write_private_key_to_jwk

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("baseurl")
    parser.add_argument("keypath")
    args = parser.parse_args()

    key = RSAKey(key=import_rsa_key_from_file(args.keypath),
                 kid="{}/{}".format(args.baseurl, rndstr()), use="sig", alg="RS256")
    write_private_key_to_jwk(key, args.baseurl + ".jwk")
