import sys
import argparse
from pathlib import Path

sys.path.append("../../../tests")
import infra.crypto

def main(args):
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True)

    tls_key_path = data_dir / 'tls_key.pem'
    tls_cert_path = data_dir / 'tls_cert.pem'
    tls_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
    tls_cert_pem = infra.crypto.generate_cert(tls_key_priv_pem, cn='localhost')
    print(f'writing {tls_key_path}')
    print(f'writing {tls_cert_path}')
    with open(tls_key_path, 'w') as f:
        f.write(tls_key_priv_pem)
    with open(tls_cert_path, 'w') as f:
        f.write(tls_cert_pem)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    args = parser.parse_args()

    main(args)