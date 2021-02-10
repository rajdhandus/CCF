import sys
sys.path.append("../../../tests")

import json
import requests
import random
from pathlib import Path

import infra.crypto
import ccf.clients

CCF_HOST = '127.0.0.1'
CCF_PORT = '8000'
CCF_CA = 'workspace/sandbox_common/networkcert.pem'

def populate_feeds():
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True)

    populate_npm_feed(data_dir)
    populate_npm_audit_feed(data_dir)

def populate_npm_feed(data_dir: Path):
    dns_name = 'npmjs.org'
    jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem, cn=dns_name)

    client = ccf.clients.CCFClient(CCF_HOST, CCF_PORT, CCF_CA)

    r = client.put(f"/app/feeds/{dns_name}", {
        "permissions": {
            #"owner": 
            #"writer":
        }
    })

    r = requests.get('https://registry.npmjs.org/-/v1/search?text=%22js%22&size=5') # 250 max
    r.raise_for_status()
    pkgs = r.json()["objects"]
    for pkg in pkgs:
        pkg_name = pkg["package"]["name"]
        item_name = pkg_name.replace('/', '_')
        url = f"https://registry.npmjs.org/{pkg_name}/latest"
        r = requests.get(url)
        r.raise_for_status()
        pkg_info = r.json()

        json_path = data_dir / f'{dns_name}_{item_name}.json'
        with open(json_path, 'w') as f:
            json.dump(pkg_info, f, indent=2)
        
        jwt = infra.crypto.create_jwt(pkg_info, jwt_key_priv_pem, cert_pem=jwt_cert_pem)
        jwt_path = data_dir / f'{dns_name}_{item_name}.jwt'
        with open(jwt_path, 'w') as f:
            f.write(jwt)
        r = client.post(f"/app/feeds/{dns_name}/{item_name}", jwt)
        data = r.body.json()

        client.wait_for_commit(r)
        r = client.get(f"/app/receipt?commit={r.seqno}")
        receipt = r.body.json()

        with open(data_dir / f'{dns_name}_{item_name}.receipt.json', 'w') as f:
            combined = {**receipt, "data": data}
            json.dump(combined, f, indent=2)
    
def populate_npm_audit_feed(data_dir: Path):
    dns_name = 'example.com'
    jwt_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    jwt_cert_pem = infra.crypto.generate_cert(jwt_key_priv_pem, cn=dns_name)

    client = ccf.clients.CCFClient(CCF_HOST, CCF_PORT, CCF_CA)

    r = client.put(f"/app/feeds/{dns_name}", {
        "permissions": {
            #"owner": 
            #"writer":
        }
    })

    for npm_receipt_path in data_dir.glob('npmjs.org*.receipt.json'):
        with open(npm_receipt_path) as f:
            npm_receipt = json.load(f)
        
        item_name = npm_receipt["data"]["itemName"] + "-audit"
        audit = {
            "subject": npm_receipt,
            "status": random.choice(["approved", "rejected"])
        }

        json_path = data_dir / f'{dns_name}_{item_name}.json'
        with open(json_path, 'w') as f:
            json.dump(audit, f, indent=2)

        jwt = infra.crypto.create_jwt(audit, jwt_key_priv_pem, cert_pem=jwt_cert_pem)
        jwt_path = data_dir / f'{dns_name}_{item_name}.jwt'
        with open(jwt_path, 'w') as f:
            f.write(jwt)
        r = client.post(f"/app/feeds/{dns_name}/{item_name}", jwt)
        data = r.body.json()

        client.wait_for_commit(r)
        r = client.get(f"/app/receipt?commit={r.seqno}")
        receipt = r.body.json()

        with open(data_dir / f'{dns_name}_{item_name}.receipt.json', 'w') as f:
            combined = {**receipt, "data": data}
            json.dump(combined, f, indent=2)

def main():
    populate_feeds()

if __name__ == '__main__':
    main()
