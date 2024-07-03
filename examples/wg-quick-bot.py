#!/usr/bin/python3
"""
Copyright (c) 2024 vypivshiy this code under the UNLICENSE or MIT License.
source: https://github.com/vypivshiy/tinytg

dummy tgbot interface for https://github.com/angristan/wireguard-install script

# features

- admin whitelist
- check wg clients
- add clients with send qrcode and conf file
- delete clients

dependencies:

- pexpect (in ubuntu server exists)

required environment variables:

#.env

    # tg users ids whitelist
    ADMIN_IDS=1,2,3
    # absolute path to script
    WG_SCRIPT_PATH=/home/user/wireguard-install.sh
    # bot token
    TOKEN=QWERTY123

"""
import os
import re
import subprocess
from contextlib import contextmanager
from typing import Match

import pexpect

from tinytg import load_dotenv, Bot, F_ALLOW_USERS, F_COMMAND, Message, logger

load_dotenv()
ADMINS = [int(i) for i in os.environ['ADMIN_IDS'].split(',') if i]
WG_SCRIPT_PATH = os.environ['WG_SCRIPT_PATH']

bot = Bot(token=os.environ['TOKEN'],
          global_rules=(F_ALLOW_USERS(*ADMINS),))


@contextmanager
def spawn_wg_install(**kwargs):
    child = pexpect.spawn(f"bash {WG_SCRIPT_PATH}", **kwargs)
    try:
        yield child
    finally:
        child.close()


def expect_wg_list():
    with spawn_wg_install() as child:
        child.expect(r"Select an option \[1\-5\]:")
        child.sendline('2')
        child.expect(pexpect.EOF)

        return '\n'.join(i.strip() for i in child.before.decode('utf-8').split('\n')).lstrip('2')


def expect_wg_revoke(num: str):
    pattern = rf'\s*{num}\) .*?'
    with spawn_wg_install() as child:
        child.expect(r"Select an option \[1\-5\]:")
        child.sendline('3')
        child.expect('Select the existing client you want to revoke')
        try:
            child.expect(pattern, timeout=1)
        except pexpect.TIMEOUT:
            return
        child.sendline(num)
        child.expect(pexpect.EOF)
        out = child.before.decode('utf-8')
        return out


def expect_wg_add(name: str):
    with spawn_wg_install() as child:
        child.expect(r"Select an option \[1\-5\]:")
        child.sendline('1')
        child.expect('Client name:')
        child.sendline(name)
        # set default values
        child.expect('Client WireGuard IPv4:')
        child.sendline('')
        child.expect('Client WireGuard IPv6:')
        child.sendline('')
        child.expect('Your client config file is in (.*)')

        file = (child.after.decode('utf-8')
                .lstrip('Your client config file is in ')
                .strip()
                # clear symbols like \x1b[0m without regex
                .split('.conf', 1)[0]
                + '.conf'
                )

        logger.debug("generate config file: %s", file)
        return file


@bot.on_message(F_COMMAND('(:?/help)|(:?/start)'))
def wg_help(m: Message):
    text = """/wg list - show available configs
/wg add <name> - add wg config
/wg del <num> - delete wg config
/help - show this help message and exit
"""
    bot.api.send_message(text, m)


@bot.on_message(F_COMMAND('/wg list'))
def wg_list(m: Message):
    out = expect_wg_list()
    bot.api.send_message(out, m)


@bot.on_message(F_COMMAND(r'/wg add'),
                parse_cb=lambda m: (re.search(r'/wg add \b([a-zA-Z\d_-]+)$', m['text']),))
def wg_add(m: Message, result):
    if not result:
        bot.api.send_message("please provide nickname", m)
        return

    lst = expect_wg_list()
    logger.debug(lst)
    name = result[1]

    logger.info("Try add user %s", name)
    if re.search(rf'\d+\) \b{name}$', lst):
        bot.api.send_message("this user already exists", m)
        return

    filename = expect_wg_add(name)
    logger.info("send config, qrcode: %s", filename)
    subprocess.run(f'qrencode -v 8 -r {filename} -o qrcode.png', shell=True)
    with open(filename, 'rb') as f:
        bot.api.send_document(f, m)
    with open('qrcode.png', 'rb') as f:
        bot.api.send_photo(f, m)


@bot.on_message(F_COMMAND(r'/wg del'),
                parse_cb=lambda m: (re.search(r'/wg del (\d+)', m['text']),))
def wg_del(m: Message, result: Match = None):
    if not result:
        bot.api.send_message("Please, provide number", m)
        return
    num = result[1]
    result = expect_wg_revoke(num)
    if not result:
        bot.api.send_message("something went wrong", m)
        return
    bot.api.send_message(f'user with {num} revoked', m)


if __name__ == '__main__':
    if not os.path.exists(WG_SCRIPT_PATH):
        logger.warning("please, provide correct wg-install script path")
        exit(1)
    bot.run()
