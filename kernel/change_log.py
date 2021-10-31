#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from config import TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_CHANGE_LOG_PATH, \
    ALI_AVD_DB_CHANGE_LOG_LATEST_NAME, ALI_AVD_DB_GIT_OWNER, ALI_AVD_DB_GIT_BRANCH


def write_change_log(new_version: str, avds: list):
    sorted_avds = sorted(avds, reverse=True)

    change_log_path = os.path.join(TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_CHANGE_LOG_PATH)
    if not os.path.isdir(change_log_path):
        os.mkdir(change_log_path)

    new_change_log_file_path_list = [new_version[:4], new_version[4: 6], new_version[6: 8],
                                     new_version[8: 10], f'{new_version[11: 15]}.txt']
    latest_file_path = os.path.join(change_log_path, ALI_AVD_DB_CHANGE_LOG_LATEST_NAME)
    content = f'version: {new_version}\n\nupdated {len(sorted_avds)} avds\n\n' \
              f'[details](https://github.com/{ALI_AVD_DB_GIT_OWNER}/' \
              f'{ALI_AVD_DB_GIT_NAME}/blob/{ALI_AVD_DB_GIT_BRANCH}/' \
              f'{ALI_AVD_DB_CHANGE_LOG_PATH}/{"/".join(new_change_log_file_path_list)})'
    with open(latest_file_path, 'w') as f:
        f.write(content)

    new_change_log_path = os.path.join(TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME,
                                       ALI_AVD_DB_CHANGE_LOG_PATH, *new_change_log_file_path_list[:-1])
    if not os.path.isdir(new_change_log_path):
        os.makedirs(new_change_log_path)

    new_change_log_file_path = os.path.join(new_change_log_path, new_change_log_file_path_list[-1])
    content = [f'version: {new_version}', '', f'updated {len(sorted_avds)} avds', ''] + sorted_avds
    with open(new_change_log_file_path, 'w') as f:
        for line in content:
            f.write(line + '\n')
