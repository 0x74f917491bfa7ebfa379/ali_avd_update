#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

TMP_FILE_PATH = os.path.join(os.getcwd(), 'tmp')

ALI_AVD_DB_GIT_NAME = 'ali_avd_db'
ALI_AVD_DB_GIT_BRANCH = 'master'
ALI_AVD_DB_GIT_OWNER = '0x74f917491bfa7ebfa379'
ALI_AVD_DB_GIT_OWNER_EMAIL = '0x74f917491bfa7ebfa379@protonmail.com'

ALI_AVD_DB_VERSION_FILE = 'version'
ALI_AVD_DB_DB_PATH = 'db'
ALI_AVD_DB_CHANGE_LOG_PATH = 'change_log'
ALI_AVD_DB_CHANGE_LOG_LATEST_NAME = 'latest.md'

CVE_LIST_URL = 'https://avd.aliyun.com/nvd/list'
HIGH_RISK_LIST_URL = 'https://avd.aliyun.com/high-risk/list'
AVD_DETAIL_URL = 'https://avd.aliyun.com/detail'

REQUESTS_TIME_OUT = 10
REQUESTS_HEADER = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
}
REQUESTS_SLEEP_TIME = 60  # 1min

CRAWL_THREADS_NUM = 8

SAVE_THREAD_SLEEP_TIME = 0.1
