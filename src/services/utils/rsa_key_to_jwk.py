#! /usr/bin/env python3

from argparse import ArgumentParser

from jwkest.jwk import RSAKey, import_rsa_key_from_file
from oic import rndstr

from oidc_fed.util import write_private_key_to_jwk, write_key_to_jwk

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("hostname")
    parser.add_argument("keypath")
    parser.add_argument("--pretty", action="store_true", default=False, help="add newlines in the output JWKs'")
    args = parser.parse_args()

    key = RSAKey(key=import_rsa_key_from_file(args.keypath),
                 kid="{}/{}".format(args.hostname, rndstr()), use="sig", alg="RS256")
    write_private_key_to_jwk(key, args.hostname + ".jwk", pretty_format=args.pretty)
    write_key_to_jwk(key, args.hostname + ".pub.jwk", pretty_format=args.pretty)
