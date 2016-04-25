# Federation operator
1. Create a private RSA key (with openssl: `openssl genrsa -out private.pem <keylen>`)
1. Create a public and private JWK from the RSA key:
   ```bash
   oidc-fed/src/services/utils/rsa_key_to_jwk.py <hostname> private.pem
   ```
1. Issue new software statements with the private JWK using `oidc-fed/src/services/fo/fo.py`:
   ```bash
    oidc-fed/src/services/fo/fo.py <entity_data>.json <hostname>.jwk
   ```

Make sure to give the public JWK, `<hostname>.pub.jwk`, together with the
software statement to any new parties joining the federation.


# Identity Provider Operator

1. Get a software statement and public JWK from all federations that the IdP
   should be part of. Make sure it includes the correct URL as `issuer`.
1. Create a private RSA key (with openssl: `openssl genrsa -out private.pem <keylen>`)
1. Convert it to a JWK with
   ```bash
   oidc-fed/src/services/utils/rsa_key_to_jwk.py <hostname> private.pem
   ```

## If you want to use an existing SAML IdP
The [SATOSA proxy](https://github.com/its-dirg/SATOSA) can be used to integrate
an existing SAML IdP into a OpenID Connect federation.

1. Configure the SATOSA proxy, see [the installation instructions first](https://github.com/its-dirg/SATOSA/tree/master/doc):
  1. For the frontend, acting as an OP, copy `oidc-fed/src/oidc_fed/satosa/oidc-fed_frontend.yaml.example`
    1. Add the private JWK (`<hostname>.jwk`) created with `rsa_key_to_jwk.py`
       under the key `root_key_jwk`.
    1. Add all software statements under the key `software_statements`.
    1. Add all federation keys under the key `federations_jwk`
  1. For the backend, acting as a SAML SP towards your IdP, see [the instructions](https://github.com/its-dirg/SATOSA/blob/master/doc/README.md#saml2-plugins).

## If you want to setup a standalone OP
1. Use the provider implementation bundled with the project
   (`oidc-fed/src/services/op/op.py`):
     1. Install the library and the dependencies:
     ```bash
     pip install . -r oidc-fed/src/services/requirements.txt
     ```
     1. Copy the example files:
     ```bash
     cp oidc-fed/src/services/op/app_config.py.example oidc-fed/src/services/op/app_config.py
     cp oidc-fed/src/services/op/config.yaml.example oidc-fed/src/services/op/config.yaml
     ```
1. Get a key and certificate for SSL/TLS (or create a self-signed certificate).
1. Configure the provider in `oidc-fed/src/services/op/config.yaml`:
   1. Add the private JWK (`<hostname>.jwk`) created with `rsa_key_to_jwk.py`
      under the key `root_key_jwk`.
   1. Add all software statements under the key `software_statements`.
   1. Add all federation JWK's under the key `federations_jwk`
1. Configure the web app in `oidc-fed/src/services/op/app_config.py`:
     1. Specify the path to the YAML file created in the above step in
        `PROVIDER_CONFIG`.
     1. Specify the [`SERVER_NAME`](http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values).
        Make sure that the host name (and optional port) matches the one in the
        issuer URL in the software statement(s).
     1. Specify the SSL/TLS key and cert in `HTTPS_KEY` and `HTTPS_CERT`
        respectively.
1. Run the provider:
   ```bash
   OIDCFED_PROVIDER_CONFIG=<path to app_config.py.example> oidc-fed/src/services/op/op.py
   ```

# Relying Party Operator

1. Get a software statement and public JWK from all federations that the RP
   should be part of. Make sure it contains the correct `redirect_uris`.
1. Create a private RSA key (with openssl: `openssl genrsa -out private.pem <keylen>`)
1. Convert it to a JWK with
   ```bash
   oidc-fed/src/services/utils/rsa_key_to_jwk.py <hostname> private.pem
   ```

## If you want to setup a standalone RP

1. Use the relying party implementation bundled with the project
   (`oidc-fed/src/services/rp/rp.py`):
     1. Install the library and the dependencies:
     ```bash
     pip install . -r oidc-fed/src/services/requirements.txt
     ```
     1. Copy the example files:
     ```bash
     cp oidc-fed/src/services/rp/app_config.py.example oidc-fed/src/services/rp/app_config.py
     cp oidc-fed/src/services/rp/config.yaml.example oidc-fed/src/services/rp/config.yaml
     ```
1. Get a key and certificate for SSL/TLS (or create a self-signed certificate).
1. Configure the relying party in `oidc-fed/src/services/rp/config.yaml`:
   1. Add the private JWK (`<hostname>.jwk`) created with `rsa_key_to_jwk.py`
      under the key `root_key_jwk`.
   1. Add all software statements under the key `software_statements`.
   1. Add all federation JWK's under the key `federations_jwk`
1. Configure the web app in `oidc-fed/src/services/rp/app_config.py`:
   1. Specify the path to the YAML file created in the above step in
      `PROVIDER_CONFIG`.
   1. Specify the [`SERVER_NAME`](http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values).
      Make sure that the software statement(s) includes `https://<server_name>/finish`
      as a `redirect_uri`.
   1. Specify the SSL/TLS key and cert in `HTTPS_KEY` and `HTTPS_CERT`
      respectively.
1. Run the relying party
   ```bash
   OIDCFED_RELYING_PARTY_CONFIG=<path to app_config.py.example> oidc-fed/src/services/rp/rp.py
   ```

## If you want to use a native app for Android

1. Coming soon...
