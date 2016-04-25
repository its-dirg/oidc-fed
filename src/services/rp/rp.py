#! /usr/bin/env python3
import ssl

import jinja2
import yaml
from flask.app import Flask
from flask.globals import request, current_app
from flask.json import jsonify
from flask.templating import render_template
from jwkest.jwk import keyrep
from oic.oic.message import AuthorizationResponse
from werkzeug.utils import redirect

from oidc_fed.relying_party import RP


def init_oidc_fed_rp(cnf):
    name = cnf["SERVER_NAME"]
    with open(cnf["RELYING_PARTY_CONFIG"]) as f:
        rp_config = yaml.safe_load(f)

    root_key = keyrep(rp_config["root_key_jwk"])
    federation_keys = [keyrep(jwk) for jwk in rp_config["federations_jwk"]]

    return RP(name, root_key, rp_config["software_statements"], federation_keys, name + "/signed_jwks")


def init_app():
    app = Flask(__name__)
    app.config.from_envvar("OIDCFED_RELYING_PARTY_CONFIG")

    template_loader = jinja2.FileSystemLoader(["templates", "../templates"])
    app.jinja_loader = template_loader

    app.rp = init_oidc_fed_rp(app.config)

    return app

app = init_app()


@app.route("/")
def index():
    return render_template("index.html", software_statements=[ss.jwt.headers["kid"] for ss in
                                                              current_app.rp.software_statements])


@app.route("/start", methods=["post"])
def make_authn():
    issuer = request.form.get("issuer")
    software_statement = request.form.get("software_statement")
    response_type = request.form.get("response_type")

    registration_data = {"response_types": [response_type]}
    if software_statement:
        registration_data["software_statements"] = current_app.rp.software_statements_jws[
            int(software_statement)]

    client_software_statement = current_app.rp.register_with_provider(issuer, registration_data)

    args = {
        "scope": ["openid profile"],
        "response_type": response_type,
        "redirect_uri": client_software_statement.msg["redirect_uris"][0],
        "response_mode": "query",
    }

    auth_req = current_app.rp.client.construct_AuthorizationRequest(request_args=args)
    login_url = auth_req.request(current_app.rp.client.authorization_endpoint)

    return redirect(login_url)


@app.route("/signed_jwks")
def signed_jwks():
    return current_app.rp.signed_jwks


@app.route("/finish")
def handle_authn_response():
    # parse authn response
    authn_response = current_app.rp.client.parse_response(AuthorizationResponse,
                                              info=request.query_string.decode("utf-8"),
                                              sformat="urlencoded")

    auth_code = None
    if "code" in authn_response:
        auth_code = authn_response["code"]
        # make token request
        args = {
            "code": auth_code,
            "client_id": current_app.rp.client.client_id,
            "client_secret": current_app.rp.client.client_secret
        }

        token_response = current_app.rp.client.do_access_token_request(scope="openid", request_args=args)
        access_token = token_response["access_token"]
        id_token = token_response["id_token"].to_dict()
        # TODO do userinfo req
    else:
        id_token = authn_response["id_token"].to_dict()
        access_token = authn_response.get("access_token")

    return jsonify(dict(auth_code=auth_code, token=access_token, id_token=id_token))


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain(app.config["HTTPS_CERT"], app.config["HTTPS_KEY"])
    app.run(debug=True, ssl_context=context)
