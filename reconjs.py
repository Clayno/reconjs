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

class ReconJSAdapter(logging.LoggerAdapter):

    def __init__(self, logger_name='reconjs'):
        self.logger = logging.getLogger(logger_name)

    def info(self, msg, *args, **kwargs):
        msg = u'{}'.format(msg)
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
        logger.debug('Unminified file found')
        text = await response.text()
        open(os.path.join(output_dir, name), 'w').write(text)
    else:
        logger.debug("Not a minified file")

async def check_map(url, session, logger, output_dir):
    url  = url.replace(".js", ".js.map")
    name = url.split('/')[-1]
    response = await session.get(url)
    text = await response.text()
    try:
        json.loads(text)
        logger.debug(f"{url} map file found")
        open(os.path.join(output_dir, name), 'w').write(text)
    except:
        logger.debug(f"{url} not map file")

async def parse_target(url, session, logger, output_dir):
    name = url.split('/')[-1]
    regex = r'''(['\"](https?:)?[/]{1,2}[^'\"> ]{5,})|(\.(get|post|ajax|load)\s*\(\s*['\"](https?:)?[/]{1,2}[^'\"> ]{5,})'''
    response = await session.get(url)
    text = await response.text()
    matches = re.findall(regex, text)
    for match in matches:
        if not re.match(r'\.(png|svg|jpg|jpeg|css)', match[0]):
            logger.info(match[0].replace('"', '').replace("'", ''))
    open(os.path.join(output_dir, name), 'w').write(text)

async def start(targets, logger, output_dir):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for target in targets:
            if re.match(r'.*\.js([^\w]+.*|$)', target):
                logger.debug(f"{target} matched")
                tasks.append(parse_target(target, session, logger, output_dir))
                tasks.append(check_map(target, session, logger, output_dir))
                tasks.append(check_unminified(target, session, logger, output_dir))
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    parser  = argparse.ArgumentParser(description="ReconJS - Recon JS files for fun and profit")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--directory', action='store', help='Output directory')
    parser.add_argument('-f', '--file', action='store', help='File of URLs')
    parser.add_argument('-u', '--url', action='store', help='Target URL')
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
    asyncio.run(start(targets, logger, output_dir))
