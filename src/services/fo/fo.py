#! /usr/bin/env python3
"""
Create signed software statements.
"""

import json
from argparse import ArgumentParser

from jwkest.jwk import keyrep

from oidc_fed.federation import Federation


def main():
    parser = ArgumentParser()
    parser.add_argument("entity_data_path", help="path to the data for the software statement")
    parser.add_argument("keypath",
                        help="path to private JWK key to use for signing the software statement")
    args = parser.parse_args()

    with open(args.keypath) as f:
        jwk = f.read()
    key = keyrep(json.loads(jwk))
    with open(args.entity_data_path) as f:
        entity_data = f.read()

    print(Federation(key).create_software_statement(json.loads(entity_data)))


if __name__ == "__main__":
    main()
