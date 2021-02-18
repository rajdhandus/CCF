# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import base64
import json
import requests
import random
import argparse
from pathlib import Path

sys.path.append("../../../tests")
import infra.crypto


def generate_npm_feed(data_dir: Path):
    name = "npm"
    issuer = f"localhost/{name}"  # localhost for local testing

    jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)

    feed_dir = data_dir / name
    feed_dir.mkdir(exist_ok=True)

    write_jwks(feed_dir, jwt_cert_pem)

    npm_search_url = (
        "https://registry.npmjs.org/-/v1/search?text=%22js%22&size=5"  # 250 max
    )
    print(f"Fetching {npm_search_url}")
    r = requests.get(npm_search_url)
    r.raise_for_status()
    pkgs = r.json()["objects"]
    for pkg in pkgs:
        pkg_name = pkg["package"]["name"]
        subject = pkg_name.replace("/", "_")
        url = f"https://registry.npmjs.org/{pkg_name}/latest"
        print(f"Fetching {url}")
        r = requests.get(url)
        r.raise_for_status()
        pkg_info = r.json()
        pkg_info["iss"] = issuer
        pkg_info["sub"] = subject

        json_path = feed_dir / f"{subject}.json".replace("/", "_")
        with open(json_path, "w") as f:
            json.dump(pkg_info, f, indent=2)

        jwt = infra.crypto.create_jwt(
            pkg_info, jwt_key_priv_pem, key_id=name, cert_pem=jwt_cert_pem
        )
        jwt_path = feed_dir / f"{subject}.jwt".replace("/", "_")
        print(f"Writing {jwt_path}")
        with open(jwt_path, "w") as f:
            f.write(jwt)


def generate_contoso_feed(data_dir: Path):
    name = "contoso"
    issuer = f"localhost/{name}"  # localhost for local testing

    jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem)

    feed_dir = data_dir / name
    feed_dir.mkdir(exist_ok=True)

    write_jwks(feed_dir, jwt_cert_pem)

    npm_feed_dir = data_dir / "npm"
    found = False
    for npm_receipt_path in npm_feed_dir.glob("*.receipt.json"):
        found = True
        print(f"Reading {npm_receipt_path}")
        with open(npm_receipt_path) as f:
            npm_receipt = json.load(f)

        subject = npm_receipt["data"]["subject"] + "-audit"
        audit = {
            "iss": issuer,
            "sub": subject,
            "artifactReference": {
                "iss": npm_receipt["data"]["issuer"],
                "sub": npm_receipt["data"]["subject"],
                "seqno": npm_receipt["data"]["seqno"],
                "hash": "tbd",
            },
            "status": random.choice(["approved", "rejected"]),
        }

        json_path = feed_dir / f"{subject}.json".replace("/", "_")
        with open(json_path, "w") as f:
            json.dump(audit, f, indent=2)

        jwt = infra.crypto.create_jwt(
            audit, jwt_key_priv_pem, key_id=name, cert_pem=jwt_cert_pem
        )
        jwt_path = feed_dir / f"{subject}.jwt".replace("/", "_")
        print(f"Writing {jwt_path}")
        with open(jwt_path, "w") as f:
            f.write(jwt)

    if not found:
        print('No receipts in npm feed folder found, run "submit_jwts.py npm" first')


def write_jwks(feed_dir, jwt_cert_pem):
    jwt_jwks_path = feed_dir / "certs"
    print(f"Writing {jwt_jwks_path}")
    with open(jwt_jwks_path, "w") as f:
        jwks = create_jwks(feed_dir.name, jwt_cert_pem)
        json.dump(jwks, f, indent=2)
    well_known_dir = feed_dir / ".well-known"
    well_known_dir.mkdir(exist_ok=True)
    discovery_path = well_known_dir / "openid-configuration"
    print(f"Writing {discovery_path}")
    with open(discovery_path, "w") as f:
        json.dump({"jwks_uri": f"https://localhost/{feed_dir.name}/certs"}, f)


def create_jwks(kid, cert_pem):
    der_b64 = base64.b64encode(infra.crypto.cert_pem_to_der(cert_pem)).decode("ascii")
    return {"keys": [{"kty": "RSA", "kid": kid, "x5c": [der_b64]}]}


def main(args):
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)

    if args.issuer == "npm":
        generate_npm_feed(data_dir)
    elif args.issuer == "contoso":
        generate_contoso_feed(data_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("issuer", choices=["npm", "contoso"])
    args = parser.parse_args()

    main(args)
