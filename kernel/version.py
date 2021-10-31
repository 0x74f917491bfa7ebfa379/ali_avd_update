#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
from datetime import datetime
from lib.utils import get_random_hex_str
from config import TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_VERSION_FILE


def get_current_version() -> (bool, str, str):
    version_file_path = os.path.join(TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_VERSION_FILE)
    with open(version_file_path, 'r') as f:
        version = f.read()
    if not re.match(r'^\d{10}-[0-9a-f]{4}$', version):
        return False, version, ''
    return True, version[:10], version[11:15]


def get_new_version() -> str:
    current_time = datetime.now().strftime('%Y%m%d%H')
    nonce = get_random_hex_str(4)
    new_version = f'{current_time}-{nonce}'
    return new_version


def write_new_version(new_version: str):
    version_file_path = os.path.join(TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_VERSION_FILE)
    with open(version_file_path, 'w') as f:
        f.write(new_version)
