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
from termcolor import colored
from urllib.parse import urljoin

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
        self.logger.info(msg, *args, **kwargs)

    def highlight(self, msg, *args, **kwargs):
        msg = u'{}'.format(colored(msg, 'yellow', attrs=['bold']))
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

async def check_unminified(url, session, logger, output_dir):
    if ".min.js" in url:
        url  = url.replace(".min.js", ".js")
        name = url.split('/')[-1]
        response = await session.get(url)
        if response.status in [401, 403, 404]:
            logger.debug("Couldn't find unminified file")
            return
        logger.highlight(f'{url} unminified file found !')
        text = await response.content.read()
        open(os.path.join(output_dir, name), 'wb').write(text)
    else:
        logger.debug("Not a minified file")

async def check_map(url, session, logger, output_dir):
    url  = url.replace(".js", ".js.map")
    name = url.split('/')[-1]
    response = await session.get(url)
    text = await response.content.read()
    text = text.decode('utf-8')
    try:
        json.loads(text)
        logger.highlight(f"{url} map file found !")
        open(os.path.join(output_dir, name), 'w').write(text)
    except:
        logger.debug(f"{url} not map file")

async def parse_js(url, session, logger, output_dir, output_file):
    regex = r'''(['\"](https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
    results = {url}
    name = url.split('/')[-1]
    response = await session.get(url)
    text = await response.content.read()
    text = text.decode('utf-8')
    matches = re.findall(regex, text)
    for match in matches:
        if not re.match(r'\.(png|svg|jpg|jpeg|css)', match[0]):
            content = match[0].replace('"', '').replace("'", '')
            if content not in list(results):
                logger.info(content)
            results.add(content)
    if output_file:
        open(os.path.join(output_dir, output_file), "a").write('\n'.join(list(results)))
    open(os.path.join(output_dir, name), 'w').write(text)

async def parse_html(url, session, logger, output_dir, output_file):
    html_links = r'''(src|href)\s*[=:]\s*['\"]?([^'\">\s]*)'''
    results = set()
    tasks = []
    response = await session.get(url)
    text = await response.content.read()
    text = text.decode('utf-8')
    matches = re.findall(html_links, text)
    for match in matches:
        content = re.split(r'''(href|src)\s*[=:]\s*[\"']?''', match[1])[0]
        joined = urljoin(url, content)
        if not re.match(r'\.(png|svg|jpg|jpeg|css)', match[0]):
            if joined not in list(results):
                results.add(joined)
                logger.debug(f'Parsing {joined}')
                if re.match(r'.*\.js([^\w]+.*|$)', joined):
                    tasks.append(parse_js(joined, session, logger, output_dir, output_file))
                    tasks.append(check_map(joined, session, logger, output_dir))
                    tasks.append(check_unminified(joined, session, logger, output_dir))
    await asyncio.gather(*tasks)

async def start(targets, logger, output_dir, output_file=None):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for target in targets:
            tasks.append(parse_html(target, session, logger, output_dir, output_file))
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="ReconJS - Recon JS files for fun and profit")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--directory', action='store', help='Output directory')
    parser.add_argument('-f', '--file', action='store', help='File of URLs')
    parser.add_argument('-u', '--url', action='store', help='Target URL')
    parser.add_argument('-o', '--output_file', action='store', help='Output file to store parsed content')
    args = parser.parse_args()
    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    setup_logger(level=level)
    logger = ReconJSAdapter()
    if args.url :
        targets = [args.url]
    if args.file:
        with open(args.file) as f:
            targets = f.readlines()
            targets = [target.strip() for target in targets]
    directory = 'output' if not args.directory else args.directory
    output_dir = os.path.join(os.getcwd(), directory)
    output_dir = os.path.join(output_dir, '')
    try:
        os.makedirs(output_dir)
    except FileExistsError:
        logger.debug("Directory already exists")
    logger.debug(f"Output dir: {output_dir}")
    if args.output_file:
        asyncio.run(start(targets, logger, output_dir, output_file=args.output_file))
    else:
        asyncio.run(start(targets, logger, output_dir))
