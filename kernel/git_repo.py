#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import git
import os
from config import TMP_FILE_PATH, ALI_AVD_DB_GIT_BRANCH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_GIT_OWNER, \
    ALI_AVD_DB_GIT_OWNER_EMAIL


def clone_ali_avd_db():
    access_token = os.getenv('ALI_AVD_TOKEN')
    url = f'https://{access_token}@github.com/{ALI_AVD_DB_GIT_OWNER}/{ALI_AVD_DB_GIT_NAME}.git'
    db_path = os.path.join(TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME)
    repo = git.Repo.clone_from(url=url, to_path=db_path, branch=ALI_AVD_DB_GIT_BRANCH, depth=1)
    return repo


def push_ali_avd_db(repo, message):
    repo.config_writer().set_value('user', 'name', ALI_AVD_DB_GIT_OWNER).release()
    repo.config_writer().set_value('user', 'email', ALI_AVD_DB_GIT_OWNER_EMAIL).release()

    repo.index.add(items=['db', 'version', 'change_log'])
    repo.index.commit(message=message)

    access_token = os.getenv('ALI_AVD_TOKEN')
    url = f'https://{access_token}@github.com/{ALI_AVD_DB_GIT_OWNER}/{ALI_AVD_DB_GIT_NAME}.git'
    remote = repo.create_remote(name='github', url=url)
    remote.push()
