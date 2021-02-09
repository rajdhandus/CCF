import sys
sys.path.append("../../../tests")

import requests
from pathlib import Path

import infra.crypto
import ccf.clients

CCF_HOST = '127.0.0.1'
CCF_PORT = '8000'
CCF_CA = 'workspace/sandbox_common/networkcert.pem'

def populate_feeds():
    tmp_dir = Path('tmp')
    tmp_dir.mkdir(exist_ok=True)

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
        
        jwt = infra.crypto.create_jwt(pkg_info, jwt_key_priv_pem, cert_pem=jwt_cert_pem)
        jwt_path = tmp_dir / f'item_{item_name}.jwt'
        with open(jwt_path, 'w') as f:
            f.write(jwt)
        r = client.post(f"/app/feeds/{dns_name}/{item_name}", jwt)

        r = client.get(f"/app/feeds/{dns_name}/{item_name}")
        with open(tmp_dir / f'item_{item_name}.receipt.json', 'w') as f:
            f.write(r.body.text())

def main():
    populate_feeds()

if __name__ == '__main__':
    main()
