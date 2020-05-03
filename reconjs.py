#!/usr/bin/python3
# coding: utf-8
import argparse
import asyncio
import aiohttp
import logging
import datetime
import re
import sys
import os
import json
from typing import Set, Tuple
from termcolor import colored
from urllib.parse import urljoin, urlparse

class ReconJSAdapter(logging.LoggerAdapter):

    def __init__(self, logger_name='reconjs'):
        self.logger = logging.getLogger(logger_name)

    def info(self, msg, *args, **kwargs):
        msg = '{}'.format(msg)
        self.logger.info(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        msg = u'{} {}'.format(colored("[x]", 'red', attrs=['bold']), msg)
        self.logger.error(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        msg = u'{} {}'.format(colored("[d]", 'green'), msg)
        self.logger.debug(msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        msg = u'{} {}'.format(colored("[+]", 'green', attrs=['bold']), msg)
        self.logger.debug(msg, *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        msg = u'{}'.format(colored(msg, 'yellow', attrs=['bold']))
        self.logger.info(msg, *args, **kwargs)

    def url(self, msg, *args, **kwargs):
        msg = u'{} {}'.format(colored("[url]", 'yellow', attrs=['bold']), msg)
        self.logger.info(msg, *args, **kwargs)

    def link(self, msg, *args, **kwargs):
        msg = u'{} {}'.format(colored("[link]", 'cyan', attrs=['bold']), msg)
        self.logger.info(msg, *args, **kwargs)

    def subdomain(self, msg, *args, **kwargs):
        msg = u'{} {}'.format(colored("[subdomain]", 'green', attrs=['bold']), msg)
        self.logger.info(msg, *args, **kwargs)

def setup_logger(level=logging.INFO, log_to_file=False, log_prefix=None, logger_name='reconjs'):
    formatter = logging.Formatter("%(message)s")
    if log_to_file:
        if not log_prefix:
            log_prefix = 'log'
        log_filename = '{}_{}.log'.format(log_prefix.replace('/', '_'), datetime.now().strftime('%Y-%m-%d'))
        fileHandler = logging.FileHandler('./logs/{}'.format(log_filename))
        fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)
    logger = logging.getLogger(logger_name)
    logger.propagate = False
    logger.addHandler(streamHandler)
    if log_to_file:
        logger.addHandler(fileHandler)
    logger.setLevel(level)
    return logger

class Target:
    def __init__(self, base_url: str):
        self.base_url: str = base_url
        self.urls: Set[str] = set()
        self.links: Set[str] = set()
        self.top_domain, self.hostname = self._extract_top_domain(base_url)
        self.subdomains: Set[str] = {self.hostname}

    def add(self, name: str, value: str) -> None:
        self.__getattribute__(name).add(value.strip())
        self.check_subdomain(value)

    def check_subdomain(self, url: str):
        try:
            top_domain, hostname = self._extract_top_domain(url)
            if self.top_domain == top_domain:
                if hostname not in self.subdomains:
                    self.subdomains.add(hostname)
                    logger.subdomain(hostname)
                    return hostname
            return None
        except Exception as e:
            return None
    
    def _extract_top_domain(self, url: str) -> Tuple[str,str]:
        hostname = urlparse(url).hostname
        if hostname.count('.') > 1:
            return '.'.join(hostname.split('.')[-2:]), hostname
        return hostname, hostname


async def save_file(url, binary_content, output_dir):
    parsed = urlparse(url)
    name = os.path.basename(parsed.path)
    file_path = os.path.join(output_dir, name)
    logger.success(f"Saving {url} to {file_path}")
    open(file_path, 'wb').write(binary_content)
    return file_path

async def download_file(url, session, output_dir):
    try:
        logger.debug(f"Downloading {url}")
        result = await session.get(url)
        return await save_file(url, await result.content.read(), output_dir)
    except Exception as e:
        #logger.error(e)
        return None

async def check_unminified(url, session, logger, output_dir):
    if ".min.js" in url:
        url  = url.replace(".min.js", ".js")
        response = await session.get(url)
        if response.status in [401, 403, 404]:
            logger.debug("Couldn't find unminified file")
            return
        logger.highlight(f'{url} unminified file found !')
        await save_file(url, await response.content.read(), output_dir)
    else:
        logger.debug("Not a minified file")

async def check_map(url, session, logger, output_dir):
    url  = url.replace(".js", ".js.map")
    response = await session.get(url)
    binary_content = await response.content.read()
    text = binary_content.decode('utf-8')
    try:
        json.loads(text)
        file_path = await save_file(url, binary_content, output_dir)
        target.add('urls', url)
        logger.highlight(f"Map file saved at {file_path}")
    except:
        logger.debug(f"{url} not map file")

async def parse_js(url, session, logger, output_dir, target):
    regex = r'''(['\"](https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
    sourcemap_file = r'//#\ssourceMappingURL=(.*)'
    name = url.split('/')[-1]
    response = await session.get(url)
    binary_content = await response.content.read()
    text = binary_content.decode('utf-8')
    matches = re.findall(regex, text)
    for match in matches:
        if not re.search(r'\.(png|svg|jpg|jpeg|css)', match[0]):
            content = match[0].replace('"', '').replace("'", '')
            if content.strip() not in target.links:
                target.add('links', content)
                logger.link(f'{content} FROM {url}')
    sourcemap_files = re.findall(sourcemap_file, text)
    fetch = []
    for file_path in sourcemap_files:
        file_path = file_path.strip()
        if re.match(r'http(s)://', file_path):
            tmp_url = file_path
        else:
            tmp_url = urljoin(url, file_path)
        file_path = await download_file(tmp_url, session, output_dir)
        if file_path:
            target.add('urls', tmp_url)
            logger.highlight(f"Map file saved at {file_path}")
    await save_file(url, binary_content, output_dir)

async def parse_html(url, session, logger, output_dir, target):
    html_links = r'''(src|href)\s*[=:]\s*['\"]?([^'\">\s]*)'''
    tasks = []
    response = await session.get(url)
    text = await response.content.read()
    text = text.decode('utf-8')
    matches = re.findall(html_links, text)
    for match in matches:
        content = re.split(r'''(href|src)\s*[=:]\s*[\"']?''', match[1])[0]
        if re.match(r'http(s)://', content):
            joined = content.strip()
        else:
            joined = urljoin(url, content.strip())
        # We don't need those crappy extensions
        if not re.search(r'\.(png|svg|jpg|jpeg|css)', joined):
            if joined.strip() not in target.urls:
                target.add('urls', joined)
                logger.url(joined)
                # Check if this is a JS file
                if re.match(r'.*\.js([^\w]+.*|$)', joined):
                    tasks.append(parse_js(joined, session, logger, output_dir, target))
                    tasks.append(check_map(joined, session, logger, output_dir))
                    tasks.append(check_unminified(joined, session, logger, output_dir))
    await asyncio.gather(*tasks)

async def start(targets, logger, directory_name=None):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for target in targets:
            path = urlparse(target.base_url).netloc
            if directory_name != None:
                path = f"{directory_name}/{path}"
            output_dir = os.path.join(os.getcwd(), path)
            output_dir = os.path.join(output_dir, '')
            try:
                os.makedirs(output_dir)
            except FileExistsError:
                logger.debug("Directory already exists")
            logger.debug(f"Output dir: {output_dir}")
            tasks.append(parse_html(target.base_url, session, logger, output_dir, target))
        await asyncio.gather(*tasks)
    with open(os.path.join(output_dir, "urls.lst"), 'w') as urls:
        urls.write('\n'.join(list(target.urls)))
    with open(os.path.join(output_dir, "endpoints.lst"), 'w') as links:
        links.write('\n'.join(list(target.links)))
    with open(os.path.join(output_dir, "subdomains.lst"), 'w') as subdomains:
        subdomains.write('\n'.join(list(target.subdomains)))


if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="ReconJS - Recon JS files for fun and profit")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--directory', action='store', help='Output directory. Default netloc')
    parser.add_argument('-f', '--file', action='store', help='File of URLs')
    parser.add_argument('-u', '--url', action='store', help='Target URL')
    args = parser.parse_args()
    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    setup_logger(level=level)
    logger = ReconJSAdapter()
    if args.url :
        targets = [Target(args.url)]
    if args.file:
        with open(args.file) as f:
            targets = f.readlines()
            targets = [Target(target.strip()) for target in targets]
    directory = None if not args.directory else args.directory
    asyncio.run(start(targets, logger, directory_name=args.directory))
