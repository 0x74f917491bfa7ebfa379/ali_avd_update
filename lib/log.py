#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging


def get_logger(logger_name):
    # get root logger
    logger = logging.getLogger(logger_name)
    # set root logger level
    logger.setLevel(logging.INFO)

    # set formatter
    formatter = logging.Formatter('[%(asctime)s] - [%(levelname)s] - [%(filename)s(:%(lineno)d)] %(message)s')

    # create stream handle
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    return logger


logger = get_logger('ali_avd_update')
