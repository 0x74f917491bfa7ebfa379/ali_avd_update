#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import random
import hashlib


def get_random_hex_str(length: int) -> str:
    return hex(random.getrandbits(length*4))[2:].zfill(length)


def calc_str_md5(s: str) -> str:
    return hashlib.md5(s.encode('l1')).hexdigest()
