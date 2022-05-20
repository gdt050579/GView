# python3
from genericpath import exists
import requests
import os
from io import BytesIO  # Python 3
import zipfile

OPENSSL_URL = os.getenv('OPENSSL_URL')
OPENSSL_ROOT_DIR = os.getenv('OPENSSL_ROOT_DIR')

if not os.path.exists(OPENSSL_ROOT_DIR):
    os.makedirs(OPENSSL_ROOT_DIR, exist_ok=True)
    
def get_and_extract(url: str) -> None:
    zip_response = requests.get(url, stream=True)
    zip = zipfile.ZipFile(BytesIO(zip_response.content))
    zip.extractall(OPENSSL_ROOT_DIR)

get_and_extract(OPENSSL_URL)
