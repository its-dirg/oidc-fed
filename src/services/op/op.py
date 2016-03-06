import json
import ssl

import jinja2
from flask import jsonify
from flask.app import Flask
from flask.globals import request
from flask.templating import render_template
from jwkest.jwk import keyrep
from oic.oic.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import NoAuthn
from oic.utils.authz import AuthzHandling
from oic.utils.sdb import SessionDB
from werkzeug.utils import redirect

from oidc_fed import OIDCFederationError
from oidc_fed.provider import OP
from oidc_fed.util import load_software_statements

PORT = 8080

app = Flask(__name__)

template_loader = jinja2.FileSystemLoader(["templates", "../templates"])
app.jinja_loader = template_loader

with open("keys/root.jwk") as f:
    jwk = json.loads(f.read())
root_key = keyrep(jwk)
federation_keys = []
federation_keys = []
for keypath in ["../fo/keys/pub/fed1.example.com.jwk", "../fo/keys/pub/fed3.example.com.jwk"]:
    with open(keypath) as f:
        federation_keys.append(keyrep(json.loads(f.read())))

name = "https://localhost:" + str(PORT)
authn_broker = AuthnBroker()

user = "tester"
authn_broker.add("password", NoAuthn(None, user))

provider = Provider(name, SessionDB(name), {}, authn_broker, None, AuthzHandling(), verify_client,
                    None)
OP = OP(name, root_key, load_software_statements("software_statements"), federation_keys,
        name + "/signed_jwks", provider, name + "/jwks")


@app.route("/")
def index():
    return render_template("index.html", software_statements=[ss.jwt.headers["kid"] for ss in
                                                              OP.software_statements])


@app.route("/signed_jwks")
def signed_jwks():
    return OP.signed_jwks

@app.route("/jwks")
def jwks():
    return jsonify(OP.jwks.export_jwks())

@app.route("/.well-known/openid-configuration")
def provider_configuration():
    response = OP.provider_configuration()
    # return response.message, response.status, response.headers
    return jsonify(json.loads(response.message))


@app.route("/registration", methods=["post"])
def client_registration():
    response = OP.register_client(request.headers, request.get_data().decode("utf-8"))
    return response.message, response.status, response.headers


@app.route("/authorization")
def authentication_endpoint():
    response = OP.provider.authorization_endpoint(request.query_string.decode("utf-8"))
    return redirect(response.message, 303)


@app.route("/token", methods=["get", "post"])
def token_endpoint():
    client_authn = request.headers.get("Authorization")

    if request.method == "GET":
        data = request.query_string
    elif request.method == "POST":
        data = request.get_data()

    response = OP.provider.token_endpoint(data.decode("utf-8"), authn=client_authn)
    return response.message, response.status, response.headers


@app.errorhandler(OIDCFederationError)
def exception_handler(error):
    response = app.make_response(str(error))
    response.status_code = 400
    return response


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain("keys/localhost.crt", "keys/localhost.key")
    app.run(port=PORT, debug=True, ssl_context=context)
