# coding: utf-8

import os
import re
import time
import yaml
import base64
import logging
import requests
import tempfile
import urlparse
import argparse
import pytesseract
from PIL import Image
from bs4 import BeautifulSoup


def check_cond(config, issue):
    try:
        y = issue['year']
        m = issue['num']
        if config and not all([eval(cond) for cond in config]):
            logging.info(u'%s, %s continue', y, m)
            return False
        else:
            return True
    except Exception as e:
        logging.error(u'cond error: %s', e)
        return True


def check_filename(filename):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
        logging.info('%s %s', 'mkdir', os.path.dirname(filename))
    if os.path.exists(filename) and len(open(filename).read()) > 100000:
        logging.info('%s %s', 'file already exists', filename)
        return False
    return True


class NSSDInfoAbstract(object):

    host = u'www.nssd.org'
    journal_search_url_template = u'http://{host}/journal/list.aspx?e=s={{journal}}'.format(host=host)
    login_url = u'http://{}/ajax/userinfo.ashx'.format(host)
    authcode_url = u'http://{}/ajax/getauthcode.ashx'.format(host)

    @classmethod
    def login_data(cls, username, password, code):
        return {
            'type': 'login',
            'zu': username,
            'zp': password,
            'zv': code,
        }

    @classmethod
    def login_success(cls, resp):
        return resp.text == u'ok'

    @classmethod
    def get_journal_from_search_result(cls, bs, name):
        for search_result in bs.find('ul', class_='cover_list').find_all('a', class_='name'):
            if search_result.text.strip() == name:
                journal_url = search_result.get('href')
                break
        if not journal_url:
            logging.error(u'没有这个期刊')
            return
        return {'url': u'http://{host}{url}'.format(host=cls.host, url=journal_url), 'name': name}

    @classmethod
    def get_years(cls, bs):
        for year in bs.find('div', id='qkyearslist').find_all('li'):
            year = year.find('a')
            logging.info('%s', year.text)
            yield {
                'url': u"http://{}{}".format(cls.host, year.get('href')),
                'year': int(year.get('title')),
            }

    @classmethod
    def get_issues(cls, bs, year):
        for issue in bs.find('div', class_='cnt', id='numlist').find_all('li'):
            issue = issue.find('a')
            href = issue.get('href')
            curr = issue.get('curr') or issue.text.split(u'年')[1].split(u'期')[0].strip()
            if curr.isdigit():
                curr = str(int(curr))
            yield {
                'url': u"http://{}{}".format(cls.host, href),
                'year': year['year'],
                'num': curr,
            }

    @classmethod
    def get_articles(cls, bs):
        for article in bs.find('table', class_='t_list').find_all('tr', class_='highlight'):
            href = article.find('a', title=u'下载').get('href')
            title = article.find('a').text
            author = article.find('td', align='center').text
            query = dict(urlparse.parse_qsl(urlparse.urlparse(href).query))
            id_ = query['id']
            yield {
                'url': href,
                'title': title,
                'author': author,
                'id': id_,
                'download_url': "http://{}{}".format(cls.host, href),
            }


class NCPSSDInfoAbstract(object):

    host = u'www.ncpssd.org'
    journal_search_url_template = u'http://{host}/journal/list.aspx?e=s={{journal}}&langType=1&keyword={{journal}}'.format(host=host)
    login_url = u'http://{}/ajax/userinfo.ashx'.format(host)
    authcode_url = u'http://{}/ajax/getauthcode.ashx'.format(host)

    @classmethod
    def login_data(cls, username, password, code):
        return {
            "action": "login",
            "uname": username,
            "password": password,
            "code": code,
            "UrlReferrer": cls.host,
        }

    @classmethod
    def login_success(cls, resp):
        return resp.json()['result'] == u'true'

    @classmethod
    def get_journal_from_search_result(cls, bs, name):
        for search_result in bs.find('div', class_='wall-t-table clr').find_all('a'):
            if search_result.text == name:
                journal_url = search_result.get('href')
                break
        if not journal_url:
            logging.error(u'没有这个期刊')
            return
        return {'url': u'http://{host}{url}'.format(host=cls.host, url=journal_url), 'name': name}

    @classmethod
    def get_issues(cls, bs):
        for year in bs.find_all('ul', class_='vol'):
            for issue in year.find_all('a'):
                href = issue.get('href')
                query = dict(urlparse.parse_qsl(urlparse.urlparse(href).query))
                y = int(query.get('years'))
                m = query.get('num')
                yield {
                    'url': u"http://{}/journal/{}".format(cls.host, href),
                    'year': y,
                    'num': m,
                }

    @classmethod
    def get_articles(cls, bs):
        articles = bs.find('div', class_='ct-detail')
        for tag in articles.find_all('a'):
            href = tag.get('href')
            title = tag.text
            query = dict(urlparse.parse_qsl(urlparse.urlparse(href).query))
            id_ = base64.b64decode(query['id'])
            yield {
                'url': href,
                'title': title,
                'id': id_,
                'download_url': "http://{}/Literature/Download.aspx?id={}&type=1".format(cls.host, id_),
            }


def main(session):

    def journals():
        for journal_name in session.config.get('journals', {}).keys():
            logging.info(u'《%s》', journal_name)
            journal_info = session.search_journal(journal_name)
            if journal_info:
                yield journal_info

    def issues(journal):
        for issue in session.get_issues(journal):
            logging.info(u'%s年 第%s期', issue['year'], issue['num'])
            if check_cond(session.config['journals'][journal['name']], issue):
                yield issue

    def articles(issue):

        def normalize_filename(s):
            i = s
            for reg in ['<\/?.+?>', '\"', '\'', ',', '[&\|\\\*^%$#@\-]', '[\'\"\\\/\b\f\n\r\t]']:
                i = re.sub(reg, '', i)
            return i

        filenames = set()
        for article in session.get_articles(issue):
            filename = normalize_filename(article['title'])
            if filename in filenames:
                logging.warning(u'%s %s', u'重名文件', filename)
                num = 2
                while u'{}{}'.format(filename, num) in filenames:
                    num += 1
                filename = u'{}{}'.format(filename, num)
            filenames.add(filename)
            article['filename'] = filename
            logging.info(u'{}:{}'.format(filename, article['id']))
            yield article

    for journal in journals():
        for issue in issues(journal):
            year = u'{}年 第{}期'.format(issue['year'], issue['num'])
            for article in articles(issue):
                filename = os.path.join(
                    os.getcwd(),
                    journal['name'],
                    year,
                    article['filename'] + '.pdf'
                )
                if not check_filename(filename):
                    continue
                session.download(article, filename)


class LoginSessionForNCPSSD(object):

    def __init__(self, host, config_file):
        self.host = host
        self.session = LoggingSession()
        if not os.path.exists(config_file):
            logging.error("Config file %s not exists.", config_file)
            self.config = {}
        else:
            try:
                self.config = yaml.load(open(config_file))
            except yaml.error.YAMLError as e:
                logging.error("YAMLError: %s", e)
                self.config = {}
        self.login()

    def login(self):
        while True:
            with tempfile.NamedTemporaryFile() as f:
                f.write(self.get(self.host.authcode_url).content)
                f.flush()
                username = self.config.get('username') or raw_input('输入用户名：')
                password = self.config.get('password') or raw_input('输入密码：')
                if 'username' not in self.config:
                    self.config['username'] = username
                if 'password' not in password:
                    self.config['password'] = password
                code = pytesseract.image_to_string(Image.open(f.name)).lower()
                code = re.sub('[^a-zA-Z0-9]', '', code)
                logging.debug('tesseract code: %s', code)
                resp = self.post(self.host.login_url, data=self.host.login_data(username, password, code))
                logging.debug(resp.text)
                logging.debug(self.session.cookies)
                if self.host.login_success(resp):
                    break

    def get(self, *args, **kwargs):
        return self.session.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        return self.session.post(*args, **kwargs)

    def search_journal(self, name):
        bs = BeautifulSoup(self.get(self.host.journal_search_url_template.format(journal=name)).text, "lxml")
        return self.host.get_journal_from_search_result(bs, name)

    def get_issues(self, journal):
        resp = self.get(journal['url'])
        bs = BeautifulSoup(resp.text, "lxml")
        return self.host.get_issues(bs)

    def get_articles(self, issue):
        resp = self.get(issue['url'])
        bs = BeautifulSoup(resp.text, "lxml")
        return self.host.get_articles(bs)

    def download(self, article, filename):
        with open(filename, 'wb') as f:
            while True:
                resp = self.get(article['download_url'])
                if not resp:
                    logging.error(u'失败次数太多，跳过文件：%s', article['title'])
                    return
                if resp.headers['Content-Type'] == 'application/octet-stream':
                    break
                else:
                    logging.error('%s %s %s', 'retry', resp.headers, resp.content)
                    time.sleep(5)
                    self.login()
            f.write(resp.content)


class LoginSessionForNSSD(LoginSessionForNCPSSD):

    def get_issues(self, journal):
        resp = self.get(journal['url'])
        bs = BeautifulSoup(resp.text, "lxml")
        for year in self.host.get_years(bs):
            resp = self.get(year['url'])
            bs2 = BeautifulSoup(resp.text, "lxml")
            for issue in self.host.get_issues(bs2, year):
                yield issue


class LoggingSession(requests.Session):

    def request(self, method, url, *args, **kwargs):
        logging.debug((method, url, args, kwargs))
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 10
        n_retries = 0
        while True:
            if n_retries == 10:
                return
            n_retries += 1
            try:
                ret = super(LoggingSession, self).request(method, url, *args, **kwargs)
                break
            except Exception as e:
                logging.error("%s %s", "request error", e)
                continue
        return ret


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--host', default='ncpssd', type=str, help=u'选择从哪个网站下载，可选ncpssd和nssd，ncpssd期刊不如nssd全，但nssd每天有下载数量限制')
    parser.add_argument('-v', '--verbose', default=0, type=int, help=u'废话等级，0---WARNING，1---INFO, 2---DEBUG, -1---没有')
    parser.add_argument('-c', '--config', default='config.yml', type=str, help=u'配置文件位置')
    parsed_args = parser.parse_args()
    if parsed_args.host == 'ncpssd':
        LoginSession = LoginSessionForNCPSSD
        InfoAbstract = NCPSSDInfoAbstract
    elif parsed_args.host == 'nssd':
        LoginSession = LoginSessionForNSSD
        InfoAbstract = NSSDInfoAbstract
    else:
        raise Exception(u'参数host不能为{}'.format(parsed_args.host))
    if parsed_args.verbose == -1:
        logging.basicConfig(level=logging.FATAL)
    elif parsed_args.verbose == 0:
        logging.basicConfig(level=logging.WARNING)
    elif parsed_args.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    elif parsed_args.verbose == 2:
        logging.basicConfig(level=logging.DEBUG)
    else:
        raise Exception(u'参数verbose不能为{}'.format(parsed_args.verbose))
    main(LoginSession(InfoAbstract, parsed_args.config))
