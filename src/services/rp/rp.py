#! /usr/bin/env python3
import json
import ssl

import jinja2
from flask.app import Flask
from flask.globals import request
from flask.json import jsonify
from flask.templating import render_template
from jwkest.jwk import keyrep
from oic.oic.message import AuthorizationResponse
from werkzeug.utils import redirect

from oidc_fed.relying_party import RP
from services.util import load_software_statements

name = "https://localhost:5000"
with open("keys/root.jwk") as f:
    jwk = json.loads(f.read())
root_key = keyrep(jwk)
federation_keys = []
for keypath in ["../fo/keys/pub/fed1.example.com.jwk", "../fo/keys/pub/fed2.example.com.jwk"]:
    with open(keypath) as f:
        federation_keys.append(keyrep(json.loads(f.read())))

RP = RP(name, root_key, load_software_statements("software_statements"), federation_keys,
        name + "/signed_jwks")

app = Flask(__name__)

template_loader = jinja2.FileSystemLoader(["templates", "../templates"])
app.jinja_loader = template_loader


@app.route("/")
def index():
    return render_template("index.html", software_statements=[ss.jwt.headers["kid"] for ss in
                                                              RP.software_statements])


@app.route("/start", methods=["post"])
def make_authn():
    issuer = request.form.get("issuer")
    software_statement = request.form.get("software_statement")

    registration_data = {}
    if software_statement:
        registration_data["software_statements"] = RP.software_statements_jws[
            int(software_statement)]

    client_software_statement = RP.register_with_provider(issuer, registration_data)

    args = {
        "scope": ["openid"],
        "response_type": "code",
        "redirect_uri": client_software_statement.msg["redirect_uris"][0]
    }

    auth_req = RP.client.construct_AuthorizationRequest(request_args=args)
    login_url = auth_req.request(RP.client.authorization_endpoint)

    return redirect(login_url)


@app.route("/signed_jwks")
def signed_jwks():
    return RP.signed_jwks


@app.route("/finish")
def handle_authn_response():
    # parse authn response
    authn_response = RP.client.parse_response(AuthorizationResponse,
                                              info=request.query_string.decode("utf-8"),
                                              sformat="urlencoded")
    auth_code = authn_response["code"]
    # make token request
    args = {
        "code": auth_code,
        "client_id": RP.client.client_id,
        "client_secret": RP.client.client_secret
    }

    token_response = RP.client.do_access_token_request(scope="openid", request_args=args)

    # TODO do userinfo req

    return jsonify(dict(auth_code=authn_response["code"], token=token_response["access_token"],
                        id_token=token_response["id_token"].to_dict()))


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_cert_chain("keys/localhost.crt", "keys/localhost.key")
    app.run(debug=True, ssl_context=context)
