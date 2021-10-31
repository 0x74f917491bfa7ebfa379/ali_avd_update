#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from kernel.git_repo import clone_ali_avd_db, push_ali_avd_db
from kernel.version import get_new_version, get_current_version, write_new_version
from kernel.craw import start_crawl
from kernel.change_log import write_change_log
from lib.log import logger


def run():
    """
    1. Clone current vulnerability data from ali_avd_db.
    2. Crawl updated vulnerability. Update or add json file.
    3. Update version and change log.
    4. Push new data to ali_avd_db.
    :return:
    """
    new_version = get_new_version()

    logger.info('-' * 64)
    logger.info('start clone db')
    repo = clone_ali_avd_db()
    logger.info('finish')
    logger.info('-' * 64 + '\n')

    flag, current_version, nonce = get_current_version()
    if not flag:
        logger.error(f'get wrong version from db: {current_version}')
        return
    logger.info(f'current version: {current_version}-{nonce}')

    logger.info('-' * 64)
    logger.info('start crawl')
    avds = start_crawl(current_version[:-2])
    logger.info('finish')
    logger.info('-' * 64 + '\n')

    logger.info('-' * 64)
    logger.info('start write new_version and change_log')
    write_new_version(new_version)
    write_change_log(new_version, avds)
    logger.info('finish')
    logger.info('-' * 64 + '\n')

    logger.info('-' * 64)
    logger.info('start push db')
    push_ali_avd_db(repo, new_version)
    logger.info('finish')
    logger.info('-' * 64 + '\n')

    logger.info('all done')


if __name__ == '__main__':
    run()
