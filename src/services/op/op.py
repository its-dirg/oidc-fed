import json
import ssl

import jinja2
import yaml
from flask import jsonify
from flask.app import Flask
from flask.globals import request, current_app
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


def init_fed_op(cnf):
    with open(cnf["PROVIDER_CONFIG"]) as f:
        provider_config = yaml.safe_load(f)

    root_key = keyrep(provider_config["root_key_jwk"])
    federation_keys = [keyrep(jwk) for jwk in provider_config["federation_jwk"]]

    authn_broker = AuthnBroker()

    name = cnf["SERVER_NAME"]
    user = "tester"
    authn_broker.add("password", NoAuthn(None, user))
    provider = Provider(name, SessionDB(name), {}, authn_broker, None, AuthzHandling(), verify_client, None)

    return OP(name, root_key, provider_config["software_statements"], federation_keys, name + "/signed_jwks",
              provider, name + "/jwks")


def init_app():
    app = Flask(__name__)

    template_loader = jinja2.FileSystemLoader(["templates", "../templates"])
    app.jinja_loader = template_loader
    app.config.from_envvar("OIDCFED_PROVIDER_CONFIG")

    app.op = init_fed_op(app.config)

    return app


app = init_app()


@app.route("/")
def index():
    return render_template("index.html", software_statements=[ss.jwt.headers["kid"] for ss in
                                                              current_app.op.software_statements])


@app.route("/signed_jwks")
def signed_jwks():
    return current_app.op.signed_jwks


@app.route("/jwks")
def jwks():
    return jsonify(current_app.op.jwks.export_jwks())


@app.route("/.well-known/openid-configuration")
def provider_configuration():
    response = current_app.op.provider_configuration()
    # return response.message, response.status, response.headers
    return jsonify(json.loads(response.message))


@app.route("/registration", methods=["post"])
def client_registration():
    response = current_app.op.register_client(request.headers.get("Authorization"),
                                              request.get_data().decode("utf-8"))
    return response.message, response.status, response.headers


@app.route("/authorization")
def authentication_endpoint():
    response = current_app.op.provider.authorization_endpoint(request.query_string.decode("utf-8"))
    return redirect(response.message, 303)


@app.route("/token", methods=["get", "post"])
def token_endpoint():
    client_authn = request.headers.get("Authorization")

    if request.method == "GET":
        data = request.query_string
    elif request.method == "POST":
        data = request.get_data()

    response = current_app.op.provider.token_endpoint(data.decode("utf-8"), authn=client_authn)
    return response.message, response.status, response.headers


@app.errorhandler(OIDCFederationError)
def exception_handler(error):
    response = app.make_response(str(error))
    response.status_code = 400
    return response


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(app.config['HTTPS_CERT'], app.config['HTTPS_KEY'])
    app.run(debug=True, ssl_context=context)
