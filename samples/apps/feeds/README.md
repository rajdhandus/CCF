Terminal 1:
```sh
./start.sh
```

Terminal 2:
```sh
python demo/generate_tls_cert.py
# need sudo for port 443
sudo python3 demo/start_issuer_server.py
```

Terminal 3:
```sh
python demo/generate_jwts.py npm
python demo/submit_jwts.py npm
# contoso references npm receipts, hence the command ordering
python demo/generate_jwts.py contoso
python demo/submit_jwts.py contoso
```
