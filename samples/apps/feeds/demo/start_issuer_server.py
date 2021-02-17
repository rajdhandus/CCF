import argparse
import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import ssl
import threading
from contextlib import AbstractContextManager

class JwtCertDiscoveryServer(AbstractContextManager):
    def __init__(self, tls_key_path: Path, tls_cert_path: Path, base_dir: Path):
        host = "localhost"
        port = 443
        
        class MyHTTPRequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                routes = {}
                for path in base_dir.iterdir():
                    if not path.is_dir():
                        continue
                    name = path.name
                    jwks_path = path / 'jwt_certs.jwks'
                    with open(jwks_path) as f:
                        jwks = json.load(f)
                    routes.update({
                        f"/{name}/.well-known/openid-configuration": {
                            "jwks_uri": f"https://{host}/{name}/keys"
                        },
                        f"/{name}/keys": jwks,
                    })

                body = routes.get(self.path)
                if body is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                body = json.dumps(body).encode()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):  # pylint: disable=arguments-differ
                print(fmt % args)

        self.httpd = HTTPServer((host, port), MyHTTPRequestHandler)
        self.httpd.socket = ssl.wrap_socket(
            self.httpd.socket,
            keyfile=str(tls_key_path),
            certfile=str(tls_cert_path),
            server_side=True,
        )
        self.thread = threading.Thread(None, self.httpd.serve_forever)
        self.thread.start()
        print(f'Listening on {host}:{port}')

    def __exit__(self, exc_type, exc_value, traceback):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


def main(args):
    data_dir = Path('data')

    tls_key_path = data_dir / 'tls_key.pem'
    tls_cert_path = data_dir / 'tls_cert.pem'
    print(f'Using {tls_key_path}')
    print(f'Using {tls_cert_path}')
    print(f'Serving JWKS from {data_dir} subfolders')
    
    with JwtCertDiscoveryServer(tls_key_path, tls_cert_path, data_dir):
        input('Press Ctrl-C to exit...')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    args = parser.parse_args()

    main(args)