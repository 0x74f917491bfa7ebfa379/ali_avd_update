#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import random
import queue
import requests
import threading
import json
import os
import re
import datetime
from lxml import etree
from urllib.parse import unquote
from config import CVE_LIST_URL, HIGH_RISK_LIST_URL, AVD_DETAIL_URL, SAVE_THREAD_SLEEP_TIME, \
    REQUESTS_HEADER, REQUESTS_TIME_OUT, REQUESTS_SLEEP_TIME, CRAWL_THREADS_NUM, TMP_FILE_PATH, \
    ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_DB_PATH
from lib.log import logger
from lib.utils import calc_str_md5


avds_list_lock = threading.Lock()
updated_avds_list_lock = threading.Lock()
db_file_lock = threading.Lock()


def sample_sleep_requests(url):
    while True:
        try:
            req = requests.get(url=url, headers=REQUESTS_HEADER, timeout=REQUESTS_TIME_OUT)
            if req.status_code != 200:
                logger.warning(f'requests have some trouble. url:{url} , status_code: {req.status_code}')
                return None
        except Exception as err:
            logger.warning(err)
            logger.info(f'requests sleep: {REQUESTS_SLEEP_TIME}')
            time.sleep(REQUESTS_SLEEP_TIME)
            continue

        return req


def get_xpath_content(url, root, xpath, attr='text'):
    item = root.xpath(xpath)
    if item:
        if attr == 'text':
            return getattr(item[0], 'text').strip()
        else:
            return item[0]
    else:
        logger.warning(f'get xpath content error. url: {url}, xpath: {xpath}')
        return ''


def get_xpath_text_br(url, root, xpath, split):
    item = root.xpath(xpath + '/text()')
    if item:
        return split.join([x.strip() for x in item if x.strip()])
    else:
        logger.warning(f'get xpath content error. url: {url}, xpath: {xpath}')
        return ''


def get_xpath_div_text(url, root, xpath, split):
    data = root.xpath(xpath)
    if data:
        result = []
        for item in data[0]:
            result.append(split.join([x.strip() for x in item.xpath('text()') if x.strip()]))
        return split.join(result)
    else:
        logger.warning(f'get xpath content error. url: {url}, xpath: {xpath}')
        return ''


def get_cve_page_number():
    url = CVE_LIST_URL

    req = sample_sleep_requests(url)
    if req is None:
        return 0

    html = etree.HTML(req.text)

    page = get_xpath_content(url, html, '/html/body/main/div/div/div[4]/span')
    re_page = re.search(r'第 1 页 / (\d+) 页', page)
    if re_page:
        return int(re_page.group(1))
    else:
        logger.error(f'get cve page number error. {page}')
        return 0


def get_high_risk_page_number():
    url = HIGH_RISK_LIST_URL

    req = sample_sleep_requests(url)
    if req is None:
        return 0

    html = etree.HTML(req.text)

    page = get_xpath_content(url, html, '/html/body/main/div[2]/div/div[3]/span')
    re_page = re.search(r'第 1 页 / (\d+) 页', page)
    if re_page:
        return int(re_page.group(1))
    else:
        logger.error(f'get high risk page number error. {page}')
        return 0


def get_cve_page_avd(page):
    url = f'{CVE_LIST_URL}?page={page}'

    req = sample_sleep_requests(url)
    if req is None:
        return []

    html = etree.HTML(req.text)

    trs = html.xpath('/html/body/main/div/div/div[3]/table/tbody/tr')
    data = []
    if trs:
        for tr in trs:
            avd = unquote(get_xpath_content(url, tr, 'td[1]/a/@href', '')[11:]).strip('?')
            if not re.match(r'^AVD-\d+-\d+$', avd):
                logger.warning(f'get a strange avd: {avd}')
                continue
            disclosure_time = get_xpath_content(url, tr, 'td[4]')
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', disclosure_time):
                logger.warning(f'get a strange disclosure time: {disclosure_time}')
                continue
            disclosure_time = disclosure_time.replace('-', '')
            data.append((avd, disclosure_time))

    return data


def get_high_risk_page_avd(page):
    url = f'{HIGH_RISK_LIST_URL}?page={page}'

    req = sample_sleep_requests(url)
    if req is None:
        return []

    html = etree.HTML(req.text)

    trs = html.xpath('/html/body/main/div[2]/div/div[2]/table/tbody/tr')
    data = []
    if trs:
        for tr in trs:
            avd = unquote(get_xpath_content(url, tr, 'td[1]/a/@href', '')[11:]).strip('?')
            if not re.match(r'^AVD-\d+-\d+$', avd):
                logger.warning(f'get a strange avd: {avd}')
                continue
            disclosure_time = get_xpath_content(url, tr, 'td[4]')
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', disclosure_time):
                logger.warning(f'get a strange disclosure time: {disclosure_time}')
                continue
            disclosure_time = disclosure_time.replace('-', '')
            data.append((avd, disclosure_time))

    return data


def get_avd_info(avd):
    url = f'{AVD_DETAIL_URL}?id={avd}'

    req = sample_sleep_requests(url)
    if req is None:
        return {}

    html = etree.HTML(req.text)

    cve = get_xpath_content(url, html, '/html/body/div[1]/div[2]/div[1]/div[2]/div[1]/div/div')

    disclosure_time = get_xpath_content(url, html, '/html/body/div[1]/div[2]/div[1]/div[2]/div[4]/div/div')

    title = html.xpath('/html/body/div[1]/div[2]/div[1]/div[1]/h5/span[2]')
    if title:
        title = title[0].text
    else:
        title = html.xpath('/html/body/div[1]/div[2]/div[1]/div[1]/h5/span')
        title = title[0].text if title else ''

    flag = html.xpath('/html/body/div[3]/div/div[1]/div[4]/div/div')
    index = 4 if flag else 2

    description = get_xpath_div_text(url, html, f'/html/body/div[3]/div/div[1]/div[{index}]/div[1]', '\n')
    solution = get_xpath_text_br(url, html, f'/html/body/div[3]/div/div[1]/div[{index}]/div[2]', '\n')

    references = []
    trs = html.xpath(f'/html/body/div[3]/div/div[1]/div[{index}]/div[3]/table/tbody/tr')
    if trs:
        for tr in trs:
            ref = get_xpath_content(url, tr, 'td[1]/a/@href', '')
            references.append(ref)

    affected_software = []
    trs = html.xpath(f'/html/body/div[3]/div/div[1]/div[{index}]/div[4]/table/tbody/tr')
    if trs:
        for i, tr in enumerate(trs):
            td = tr.xpath('td')
            if not td:
                continue
            text = td[0].xpath('text()')
            if not text or text[0].strip() != '运行在以下环境':
                continue
            if i + 1 >= len(trs):
                break

            _type = get_xpath_content(url, trs[i+1], 'td[1]')
            flag = trs[i+1].xpath('td[2]/a')
            vendor = get_xpath_content(url, trs[i+1], 'td[2]/a') if flag else get_xpath_content(url, trs[i+1], 'td[2]')
            flag = trs[i+1].xpath('td[3]/a')
            prod = get_xpath_content(url, trs[i+1], 'td[3]/a') if flag else get_xpath_content(url, trs[i+1], 'td[3]')
            flag = trs[i+1].xpath('td[4]/a')
            version = get_xpath_content(url, trs[i+1], 'td[4]/a') if flag else get_xpath_content(url, trs[i+1], 'td[4]')
            flag = trs[i+1].xpath('td[5]/b')
            _from = get_xpath_text_br(url, trs[i+1], 'td[5]/b', ' ') if flag else ''
            flag = trs[i+1].xpath('td[6]/b')
            up_to = get_xpath_text_br(url, trs[i+1], 'td[6]/b', ' ') if flag else ''

            affected_software.append({'type': _type, 'vendor': vendor, 'production': prod,
                                      'version': version, 'from': _from, 'up_to': up_to})

    score = get_xpath_content(url, html, '/html/body/div[3]/div/div[2]/div/div[1]/div/div/header/div[2]')

    ali_or_nvd = get_xpath_content(url, html, '/html/body/div[3]/div/div[2]/div/div[1]/div/div/header/div[1]')

    ali_assess_info = {}
    cvss = ''
    if ali_or_nvd == '阿里云评分':
        is_ali_assess = True
        ali_assess_key = ('attack_vector', 'attack_complexity', 'privileges_required', 'scope',
                          'exp_maturity', 'patch', 'confidentiality_impact', 'integrity_impact',
                          'server_risk', 'whole_network_number')
        for i, key in enumerate(ali_assess_key):
            item = get_xpath_content(url, html, f'/html/body/div[3]/div/div[2]/div/div[1]/div/div/ul/li[{i+1}]/div[2]')
            ali_assess_info[key] = item
    else:
        is_ali_assess = False
        cvss = get_xpath_content(url, html, '/html/body/div[3]/div/div[2]/div/div[1]/div/div/div/div')

    cwe = []
    trs = html.xpath(f'/html/body/div[3]/div/div[2]/div/div[2]/div/div/table/tbody/tr')
    if trs:
        for tr in trs:
            flag = tr.xpath('td[1]/a')
            cwe_id = get_xpath_content(url, tr, 'td[1]/a') if flag else get_xpath_content(url, tr, 'td[1]')
            if not re.match(r'^CWE-\d+$', cwe_id):
                continue
            cwe_description = get_xpath_content(url, tr, 'td[2]')
            cwe.append({'cwe_id': cwe_id, 'cwe_description': cwe_description})

    data = {
        'avd': avd,
        'cve': cve,
        'title': title,
        'disclosure_time': disclosure_time,
        'description': description,
        'solution': solution,
        'references': references,
        'affected_software': affected_software,
        'is_ali_assess': is_ali_assess,
        'ali_assess_info': ali_assess_info,
        'cvss': cvss,
        'score': score,
        'cwe': cwe
    }
    return data


def get_avds(current_version: str) -> list:
    avds = set()

    logger.info('start get cve page')
    cve_page_number = get_cve_page_number()
    logger.info(f'cve page number: {cve_page_number}')

    # Extend the time range to avoid delays in official updates
    current_date = datetime.datetime.strptime(current_version, '%Y%m%d')
    delta_date = datetime.timedelta(days=180)

    break_flag = False
    for page in range(1, cve_page_number + 1):
        data = get_cve_page_avd(page)
        logger.info(f'get {len(data)} items from page {page}')
        for avd, disclosure_time in data:
            disclosure_date = datetime.datetime.strptime(disclosure_time, '%Y%m%d')
            if disclosure_date >= current_date - delta_date:
                avds.add(avd)
            else:
                break_flag = True
                break
        if break_flag:
            logger.info(f'disclosure time greater than current version in page {page}. break')
            break

    logger.info('start get high risk page')
    high_risk_page_number = get_high_risk_page_number()
    logger.info(f'high risk page number: {high_risk_page_number}')

    break_flag = False
    for page in range(1, high_risk_page_number + 1):
        data = get_high_risk_page_avd(page)
        logger.info(f'get {len(data)} items from page {page}')
        for avd, disclosure_time in data:
            disclosure_date = datetime.datetime.strptime(disclosure_time, '%Y%m%d')
            if disclosure_date >= current_date - delta_date:
                avds.add(avd)
            else:
                break_flag = True
                break
        if break_flag:
            logger.info(f'disclosure time greater than current version in page {page}. break')
            break

    avds = list(avds)
    random.shuffle(avds)

    return avds


def detail_crawl(avds_queue: queue.Queue, avds: list, _id: int):
    count = 0
    while True:
        with avds_list_lock:
            if avds:
                avd = avds.pop()
            else:
                break

        data = get_avd_info(avd)
        if data:
            count += 1
            avds_queue.put_nowait((_id, 'work', data))
            logger.info(f'[detail crawl {_id}] got {avd} data')
        else:
            logger.warning(f'[detail crawl {_id}] got {avd} data failed')

    avds_queue.put_nowait((_id, 'stop', None))
    logger.info(f'[detail crawl {_id}] finish. got {count} avds data')


def save_avd_data(data: dict) -> bool:
    avd = data['avd']
    hash_value = calc_str_md5(avd)
    prefix = hash_value[:2]
    path = os.path.join(TMP_FILE_PATH, ALI_AVD_DB_GIT_NAME, ALI_AVD_DB_DB_PATH, prefix)
    if not os.path.isdir(path):
        os.makedirs(path)

    sub_db_file_path = os.path.join(path, f'{prefix}_sub_db.json')
    with db_file_lock:
        if os.path.isfile(sub_db_file_path):
            with open(sub_db_file_path, 'r') as f:
                sub_db_data = json.loads(f.read())
        else:
            sub_db_data = []

        is_updated = True
        tmp_avds = [item['avd'] for item in sub_db_data]
        if avd in tmp_avds:
            index = tmp_avds.index(avd)
            if data == sub_db_data[index]:
                is_updated = False
            else:
                sub_db_data[index] = data
        else:
            sub_db_data.append(data)

        if is_updated:
            with open(sub_db_file_path, 'w') as f:
                f.write(json.dumps(sub_db_data))

    return is_updated


def save_info(avds_queue: queue.Queue, updated_avds: list):
    stop_signal_num = 0

    while True:
        if avds_queue.qsize() == 0:
            time.sleep(SAVE_THREAD_SLEEP_TIME)
            continue

        _id, op, data = avds_queue.get_nowait()

        if op == 'work':
            logger.info(f'[save info] get work signal from {_id}')
            is_updated = save_avd_data(data)
            if is_updated:
                with updated_avds_list_lock:
                    updated_avds.append(data['avd'])

        elif op == 'stop':
            logger.info(f'[save info] get stop signal from {_id}')
            stop_signal_num += 1
            if stop_signal_num == CRAWL_THREADS_NUM:
                break

    logger.info(f'[save info] get {stop_signal_num} stop signal. finish')


def get_details(avds: list) -> list:
    avds_backup = avds[::]
    updated_avds = []
    avds_queue = queue.Queue()

    detail_crawl_threads = []
    for _id in range(CRAWL_THREADS_NUM):
        t = threading.Thread(target=detail_crawl, args=(avds_queue, avds_backup, _id))
        t.start()
        detail_crawl_threads.append(t)

    save_info_thread = threading.Thread(target=save_info, args=(avds_queue, updated_avds))
    save_info_thread.start()

    for thread in detail_crawl_threads:
        thread.join()
    save_info_thread.join()

    return updated_avds


def start_crawl(current_version: str) -> list:
    logger.info('start get updated avds')
    avds = get_avds(current_version)
    logger.info(f'get {len(avds)} avds need to update')

    if not avds:
        logger.info('no need to get updated avds details')
        return list()

    logger.info('start get updated avds details')
    updated_avds = get_details(avds)
    logger.info(f'finish')

    return updated_avds
