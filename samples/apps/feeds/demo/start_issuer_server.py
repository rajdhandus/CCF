# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl


def main():
    data_dir = Path("data").resolve()

    tls_key_path = data_dir / "tls_key.pem"
    tls_cert_path = data_dir / "tls_cert.pem"
    print(f"Using {tls_key_path}")
    print(f"Using {tls_cert_path}")
    print(f"Serving {data_dir}")

    host = "localhost"
    port = 443

    os.chdir(data_dir)
    httpd = HTTPServer((host, port), SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile=str(tls_key_path),
        certfile=str(tls_cert_path),
        server_side=True,
    )
    print(f"Listening on {host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
