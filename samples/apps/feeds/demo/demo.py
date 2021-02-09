import sys
sys.path.append("../../../tests")

from pathlib import Path

import infra.crypto
import ccf.clients

CCF_HOST = '127.0.0.1'
CCF_PORT = '8000'
CCF_CA = 'workspace/sandbox_common/networkcert.pem'

def populate_feeds():
    tmp_dir = Path('tmp')
    tmp_dir.mkdir(exist_ok=True)

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

    item_name = "foo"
    claims = {}
    jwt = infra.crypto.create_jwt(claims, jwt_key_priv_pem, cert_pem=jwt_cert_pem)
    with open(tmp_dir / 'item_1.jwt', 'w') as f:
        f.write(jwt)
    r = client.post(f"/app/feeds/{dns_name}/{item_name}", jwt)

    r = client.get(f"/app/feeds/{dns_name}/{item_name}")
    with open(tmp_dir / 'item_1.receipt.json', 'w') as f:
        f.write(r.body.text())

def main():
    populate_feeds()

if __name__ == '__main__':
    main()
