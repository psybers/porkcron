#!/usr/bin/env python3

import json
import logging
import os
import sys
from urllib import request

# https://porkbun.com/api/json/v3/documentation
DEFAULT_API_URL = "https://porkbun.com/api/json/v3"
DEFAULT_CERTIFICATE_PATH = "/etc/porkcron"
DEFAULT_PRIVATE_KEY_PATH = "/etc/porkcron"
DEFAULT_CERTIFICATE_FILE = "certificate.pem"
DEFAULT_PRIVATE_KEY_FILE = "private_key.pem"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info("running SSL certificate renewal script")

    domains = getenv_or_exit("DOMAINS").split(',')
    api_key = getenv_or_exit("API_KEY")
    secret_key = getenv_or_exit("SECRET_KEY")

    for domain in domains:
        domain = domain.strip()

        url = os.getenv("API_URL", DEFAULT_API_URL) + "/ssl/retrieve/" + domain
        body = json.dumps({"apikey": api_key, "secretapikey": secret_key}).encode()
        headers = {"Content-Type": "application/json"}

        logging.info(f"\tdownloading SSL bundle for {domain}")
        req = request.Request(url, data=body, headers=headers, method="POST")
        with request.urlopen(req) as resp:
            data = json.load(resp)

        if data["status"] == "ERROR":
            logging.error(data["message"])
            sys.exit(1)

        certificate_path = os.getenv("CERTIFICATE_PATH", DEFAULT_CERTIFICATE_PATH)
        certificate_path = os.path.join(certificate_path, domain)
        os.makedirs(certificate_path, exist_ok=True)
        certificate_path = os.path.join(certificate_path, os.getenv("CERTIFICATE_FILE", DEFAULT_CERTIFICATE_FILE))
        logging.info(f"\t\tsaving certificate to {certificate_path}")
        with open(certificate_path, "w") as f:
            f.write(data["certificatechain"])

        private_key_path = os.getenv("PRIVATE_KEY_PATH", DEFAULT_PRIVATE_KEY_PATH)
        private_key_path = os.path.join(private_key_path, domain)
        os.makedirs(private_key_path, exist_ok=True)
        private_key_path = os.path.join(private_key_path, os.getenv("PRIVATE_KEY_FILE", DEFAULT_PRIVATE_KEY_FILE))
        logging.info(f"\t\tsaving private key to {private_key_path}")
        with open(private_key_path, "w") as f:
            f.write(data["privatekey"])

        logging.info("\tSSL certificate has been successfully renewed")


def getenv_or_exit(key: str) -> str:
    value = os.getenv(key)
    if value is not None:
        return value

    logging.error(f"{key} is required but not set")
    sys.exit(1)


if __name__ == "__main__":
    main()
