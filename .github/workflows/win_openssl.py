# python3
from genericpath import exists
import requests
import os
from io import BytesIO  # Python 3
import zipfile

OPENSSL_URL = os.getenv('OPENSSL_URL')
OPENSSL_PATH = os.getenv('OPENSSL_PATH')

if not os.path.exists(OPENSSL_PATH):
    os.makedirs(OPENSSL_PATH, exist_ok=True)
    
def get_and_extract(url: str) -> None:
    zip_response = requests.get(url, stream=True)
    zip = zipfile.ZipFile(BytesIO(zip_response.content))
    zip.extractall(OPENSSL_PATH)

get_and_extract(OPENSSL_URL)
