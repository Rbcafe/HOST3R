#!/usr/bin/env python
# coding: utf-8
# HOST3R
# Inited By Ahmed Aboul-Ela @aboul3la
# Modded By Rbcafe
# sudo pip install argparse dnspython requests
# git clone https://github.com/rbcafe/host3r

#######################
# IMPORT
#######################

import re
import sys
import os
import argparse
import time
import requests
if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib
import hashlib
import random
import multiprocessing
import threading
import traceback
import dns.resolver
import socket
from collections import Counter
if sys.version > '3':
    from queue import Queue
else:
    from Queue import Queue

#######################
# CHECK REQUESTED PACKAGE
#######################

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

#######################
# CHECK WIN
#######################

is_windows = sys.platform.startswith('win')

#######################
# BANNER
#######################

def banner():
    print ("""
::::::::::::::::::::cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
::::::::::::::::::ccccccccc;;;;;;ccccccccccccccccclcllllllllllcccccccccccccccccc
::::::::::::::::cccccc:::,,'.;;cc;,cccccccclllllllllllllllllllllllllllllcccccccc
::::::::::::::ccccccc:::',c;k0KKKKKko:lllllllllllllllllllllllllllllllllllllllccc
:::::::::::::ccccccc:;;'cdxxKKKKKKKKK0clllllllllllllllllllllllllllllllllllllllll
:::::::::::cccccccc:;;'cxxxOKKKKKKKKKK0;llllllllllllllllllllllllllllllllllllllll
:::::::::ccccccccc:;;;.oxxxkK0Ok0KKK0O0x:lllllllllllllllllllllllllllllllllllllll
::::::::ccccccccccc;;;,cxxxoOKNNXOd0XNX0:llllllllllllllloooollllllllllllllllllll
::::;c;col:cccccccc;;;;'xxdxMxNMMMOKMMMx0:lllloooooollccoc:ccoooooooolllllllllll
;,;;d0K:oxc;cccccccc;;'.:;:oWMMMMWdkOOOxclooooooool:;;lddcOOo:loooooooooolllllll
':0KOlcOK00O,cccccc:;;''.olddO00koxkxdoc;oooooool:::,kk0KO:oOOx:oooooooooooollll
,;,oOdckdxKX;ccccccc:;;;:oxxxooodddddkOOdcllcoooc::;:kKodkcxdck:oooooooooooooool
,';lldkKxKKKKo:cccc:;;;;cldo:xOOOOOOOOOOOodocool:;:dx0KkKKKKKxcooooooooooooooooo
,,,':xxOKKKKKK0dccc::;;;,'x:dOOOOOOOOOOkdoccol::cdkOKKKKKKKolooooooooooooooooooo
;,,,,,oxk0KKKKKKKxlcl:;;;'xlckOOOOOOOOko:ccc;:oxk0KKKKKKKxcooooooooooooooooooooo
::;,,;,;dxO0KKKKKKKOo:,,;,xxolodkOkxdccl:c,cxxO0KKKKKKKOlodddddddooooooooooooooo
:cc:;;;;,cxxk0KKKKKKKKcOl,dxxO0kolxOX:ocOXKOkxKKKKKKK0dlddddddddddddoooooooooooo
ccccc:;;;,,cxxk0KKKKKxOMM0dXMMMKOWxkXcOMoNWMMWkkKKKKdlddddddddddddddddoooooooooo
:cccccc:;;;,,cxxk0KKxKMMMMNdKKKkMMMXkN0OxKMMMMMXxKxldddddddddddddddddddooooooooo
ccccccccc:;;;;,:dxdkWMMMMMMKKMMMMMMMMMMOKMMMMMMMX;ddddddddddddddddddddddoooooooo
ccccccccccc:;;;,.oONWMMMMMMMMMMMMMMMMMMMxWMMMMNkloddddddddddddddddddddddoooooooo
cccccccccccc:;;;;;lxOXNWMMMMMMMMMMMMMMMMKl0kxolddddddddddddddddddddddddddooooooo
ccccccccccccccc:::;;;'xOKMMMMMMMMMMMMMMMMKxldddddddddddddddddddddddddddddooooooo
ccccccccccccccclc:;;c0XWMMMMMMMMMMMMMMMMMMMNdldddddddddddddddddddddddddddooooooo
:ccccccccccccccc;;;kXXWMMMMMMMMMMMMMMMMMMMMMM0ldddddddddddddddddddddddddoooooooo
cccccccccccccc:;,cKXXXMMMMMMMMMMMMMMMMMMMMMMMM0cdddddddddddddddddddddddooooooooo
ccccccccccccc;;,cXXXXWMMMMMMMMMMMMMMMMMMMMMMMMMoodddddddddddddddddddddoooooooooo
:ccccccccccc;;;;XXXXXMWX0OOOkkkOOOOxxOOOO0KNMMM0cddddddddddddddddddooooooooooooo
::ccccccccc;;;,dKkdoc:;clodxxxkkOOOdd0OOOkdc:cxkcoddddddddddddddddoooooooooooooo
::cccc:::::;;;;..;:::cooooooollc:::;;;:::cloooc.oodxxdxddddddddddooooooooooooooo

#####################################
# HOST3R
# Inited By Ahmed Aboul-Ela @aboul3la
# Modded By Rbcafe
#####################################
""")

#######################
# ERROR
#######################

def parser_error(errmsg):
    banner()
    print ("[!] NOTE : USAGE : python " + sys.argv[0] + " [Options] use -h")
    print ("[!] NOTE : ERROR : " + errmsg + "\n")
    sys.exit()

#######################
# ARGPARSE
#######################

def parse_args():
    banner()
    parser = argparse.ArgumentParser()
    parser.error = parser_error
    parser._optionals.title = "[!] NOTE : OPTIONS "
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-o', '--output')
    parser.add_argument('-v', '--verbose', nargs='?', default=False)
    parser.add_argument('-e', '--exception', nargs='?', default=False)
    parser.add_argument('-6', '--ipv6', nargs='?', default=False)
    return parser.parse_args()
#######################
# WRITE FILE
#######################

def write_file(filename, subdomains):
    print ("\n[!] NOTE : SAVING RESULT : %s" % (filename))
    with open(str(filename), 'wb') as f:
        f.write("#####################################\n#HOST3R\n#####################################\n\n")
        f.write("#BLOCK IPv4 SUBDOMAINS :\n\n")
        for subdomain in subdomains:
            f.write("127.0.0.1  " + subdomain + "\r\n")
        if ipv6:
            f.write("\n#BLOCK IPv6 SUBDOMAINS :\n\n")
            for subdomain in subdomains:
                f.write("::1  " + subdomain + "\r\n")

#######################
# BASIC
#######################

class enumratorBase(object):

    def __init__(self, base_url, engine_name, domain, subdomains=None):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 10
        self.base_url = base_url
        self.engine_name = engine_name
        self.print_banner()

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def send_req(self, query, page_no=1):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            resp = None
            pass
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def extract_domains(self, resp):
        return

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        return

    def generate_query(self):
        return

    def get_page(self, num):
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        prev_subdomains = []
        retries = 0
        while flag:
            query = self.generate_query()
            count = query.count(self.domain)
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)
            if self.check_max_pages(page_no):
                return self.subdomains
            resp = self.send_req(query, page_no)
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3:
                    return self.subdomains
            prev_links = links
            self.should_sleep()
        return self.subdomains

#######################
# ENUMERATOR THREADED
#######################

class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):

    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)

#######################
# GOOGLE
#######################

class GoogleEnum(enumratorBaseThreaded):

    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(
            base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass
        return links_list

    def check_response_errors(self, resp):
        if 'Our systems have detected unusual traffic' in resp:
            if verbose:
                print ("[!] NOTE : ERROR : GOOGLE BLOCK")
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

#######################
# YAHOO
#######################

class YahooEnum(enumratorBaseThreaded):

    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(
            base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx2 = re.compile(
            '<span class=" fz-15px fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile(
            '<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub("<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass
        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query

#######################
# ASK
#######################

class AskEnum(enumratorBaseThreaded):

    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(
            self, base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass
        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query

#######################
# BING
#######################

class BingEnum(enumratorBaseThreaded):

    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumratorBaseThreaded.__init__(
            self, base_url, self.engine_name, domain, subdomains, q=q)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass
        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query

#######################
# BAIDU
#######################

class BaiduEnum(enumratorBaseThreaded):

    def __init__(self, domain, subdomains=None, q=None):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        enumratorBaseThreaded.__init__(
            self, base_url, self.engine_name, domain, subdomains, q=q)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        if verbose:
                            print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(
                domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(
                domain=self.domain)
        return query

#######################
# NETCRAFT
#######################

class NetcraftEnum(multiprocessing.Process):

    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'http://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "Netcraft"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 10
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def req(self, url, cookies=None):
        cookies = cookies or {}
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        }
        try:
            resp = self.session.get(
                url, headers=headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            resp = None
        return resp

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def get_next(self, resp):
        link_regx = re.compile('<A href="(.*?)"><b>Next page</b></a>')
        link = link_regx.findall(resp)
        link = re.sub('host=.*?%s' % self.domain, 'host=%s' %
                      self.domain, link[0])
        url = 'https://searchdns.netcraft.com' + link
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain=self.domain)
        while True:
            resp = self.get_response(self.req(url, cookies))
            self.extract_domains(resp)
            if not 'Next page' in resp:
                return self.subdomains
                break
            url = self.get_next(resp)

    def extract_domains(self, resp):
        link_regx = re.compile(
            '<a href="https://toolbar.netcraft.com/site_report\?url=(.*)">')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass
        return links_list

#######################
# DNS DUMPSTER
#######################

class DNSdumpster(multiprocessing.Process):

    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'https://dnsdumpster.com/'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.live_subdomains = []
        self.session = requests.Session()
        self.engine_name = "DNSdumpster"
        multiprocessing.Process.__init__(self)
        self.threads = 70
        self.lock = threading.BoundedSemaphore(value=self.threads)
        self.q = q
        self.timeout = 25
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def check_host(self, host):
        is_valid = False
        Resolver = dns.resolver.Resolver()
        Resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.lock.acquire()
        try:
            ip = Resolver.query(host, 'A')[0].to_text()
            if ip:
                if verbose:
                    print ("[-] DIGGING : %s : %s" % (self.engine_name, host))
                is_valid = True
                self.live_subdomains.append(host)
        except:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            pass
        self.lock.release()
        return is_valid

    def req(self, req_method, url, params=None):
        params = params or {}
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'https://dnsdumpster.com'
        }
        try:
            if req_method == 'GET':
                resp = self.session.get(
                    url, headers=headers, timeout=self.timeout)
            else:
                resp = self.session.post(
                    url, data=params, headers=headers, timeout=self.timeout)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def get_csrftoken(self, resp):
        csrf_regex = re.compile(
            "<input type='hidden' name='csrfmiddlewaretoken' value='(.*?)' />", re.S)
        token = csrf_regex.findall(resp)[0]
        return token.strip()

    def enumerate(self):
        resp = self.req('GET', self.base_url)
        token = self.get_csrftoken(resp)
        params = {'csrfmiddlewaretoken': token, 'targetip': self.domain}
        post_resp = self.req('POST', self.base_url, params)
        self.extract_domains(post_resp)
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.check_host, args=(subdomain,))
            t.start()
            t.join()
        return self.live_subdomains

    def extract_domains(self, resp):
        tbl_regex = re.compile(
            '<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)
        link_regex = re.compile('<td class="col-md-4">(.*?)<br>', re.S)
        links = []
        try:
            results_tbl = tbl_regex.findall(resp)[0]
        except IndexError:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            results_tbl = ''
        links_list = link_regex.findall(results_tbl)
        links = list(set(links_list))
        for link in links:
            subdomain = link.strip()
            if not subdomain.endswith(self.domain):
                continue
            if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                self.subdomains.append(subdomain.strip())
        return links

#######################
# VIRUS TOTAL
#######################

class Virustotal(multiprocessing.Process):

    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'https://www.virustotal.com/en/domain/{domain}/information/'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "Virustotal"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 10
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def req(self, url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        }
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile(
            '<div class="enum.*?">.*?<a target="_blank" href=".*?">(.*?)</a>', re.S)
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            pass

#######################
# THREATCROWD
#######################

class ThreatCrowd(multiprocessing.Process):

    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "ThreatCrowd"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 50
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def req(self, url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        }
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            import json
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            return
        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            pass

#######################
# CRTSEARCH
#######################

class CrtSearch(multiprocessing.Process):

    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'https://crt.sh/?q=%25.{domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "SSL Certificates"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 25
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def req(self, url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        }
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<TD>(.*?)</TD>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain) or '*' in subdomain:
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            pass

#######################
# PassiveDNS
#######################

class PassiveDNS(multiprocessing.Process):

    def __init__(self, domain, subdomains=None, q=None, lock=threading.Lock()):
        subdomains = subdomains or []
        self.base_url = 'http://ptrarchive.com/tools/search.htm?label={domain}'
        self.domain = urlparse.urlparse(domain).netloc
        self.subdomains = []
        self.session = requests.Session()
        self.engine_name = "PassiveDNS"
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q
        self.timeout = 25
        self.print_banner()
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)
        return

    def print_banner(self):
        print ("[-] SEARCHING : %s" % (self.engine_name))
        return

    def req(self, url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/40.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
        }
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
                print ("[!] NOTE : ERROR : %s" % e)
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        if hasattr(response, "text"):
            return response.text
        else:
            return response.content

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regx = re.compile('<td>(.*?)</td>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                if self.domain not in link:
                    continue
                subdomain = link[:link.find('[')].strip()
                if subdomain not in self.subdomains and subdomain != self.domain and subdomain.endswith(self.domain):
                    if verbose:
                        print ("[-] DIGGING : %s : %s" % (self.engine_name, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            if exception:
                print ("[!] NOTE : ERROR : %s" % (self.engine_name))
            pass

#######################
# MAIN
#######################

def main():
    args = parse_args()
    domain = args.domain
    savefile = args.output
    google_list = []
    bing_list = []
    baidu_list = []
    search_list = set()
    if is_windows:
        subdomains_queue = list()
    else:
        subdomains_queue = multiprocessing.Manager().list()

#######################
# PARAMETERS
#######################

    global verbose, ipv6, exception
    exception = args.exception
    ipv6 = args.ipv6
    verbose = args.verbose
    if verbose or verbose is None:
        verbose = True
    if ipv6 or ipv6 is None:
        ipv6 = True
    if exception or exception is None:
        exception = True

#######################
# DOMAIN CHECK
#######################

    domain_check = re.compile(
        "^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        print ("\n[!] NOTE : ERROR : ENTER A VALID DOMAIN\n")
        sys.exit()
    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://' + domain

#######################
# BANNER
#######################

    banner()
    parsed_domain = urlparse.urlparse(domain)
    print ("#####################################\n")
    print ("[!] NOTE : ENUMERATING SUBDOMAINS TO ADD FOR : %s" % parsed_domain.netloc)
    print ("\n#####################################\n")
    if verbose:
        print ("[!] NOTE : VERBOSITY ACTIVATED")
    if ipv6:
        print ("[!] NOTE : IPV6 TO HOST ACTIVATED")
    if exception:
        print ("[!] NOTE : EXCEPTIONS NOTICES ACTIVATED")

#######################
# ENGINE ENUMERATION
#######################

    enums = [enum(domain, verbose, q=subdomains_queue) for enum in (BaiduEnum, YahooEnum, GoogleEnum, BingEnum,AskEnum, NetcraftEnum, Virustotal, ThreatCrowd, CrtSearch, PassiveDNS)]
    #enums = [enum(domain, verbose, q=subdomains_queue) for enum in (BaiduEnum, YahooEnum, GoogleEnum, BingEnum,AskEnum, NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd, CrtSearch, PassiveDNS)]

    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()
    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)
    if subdomains:
        subdomains = sorted(subdomains)
        print ("\n#####################################\n")
        print ("[!] NOTE : SUBDOMAINS LIST : %s TO ADD " % len(subdomains))
        print ("\n#####################################\n")
        print ("#####################################\n#HOST3R\n#####################################\n")
        print ("#BLOCK IPv4 SUBDOMAINS : %s\n" % parsed_domain.netloc)
        for subdomain in subdomains:
            print ("127.0.0.1  " + subdomain)
        if ipv6:
            print ("\n#BLOCK IPv6 SUBDOMAINS : %s\n" % parsed_domain.netloc)
            for subdomain in subdomains:
                print ("::1  " + subdomain)
        if savefile:
            write_file(savefile, subdomains)
        print ("\n#####################################\n")

if __name__ == "__main__":
    main()
