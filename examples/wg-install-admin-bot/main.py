import os
import re
import subprocess
from typing import Match

import pexpect

from tinytg import load_dotenv, Bot, F_ALLOW_USERS, F_COMMAND, Message

load_dotenv()
ADMINS = [int(i) for i in os.environ['ADMIN_IDS'].split(',')]
WG_SCRIPT_PATH = os.environ['WG_SCRIPT_PATH']

bot = Bot(token=os.environ['TOKEN'],
          global_rules=(F_ALLOW_USERS(*ADMINS),))


def expect_wg_list():
    child = pexpect.spawn(WG_SCRIPT_PATH)
    child.expect(r"Select an option \[1\-5\]:")
    child.sendline('2')
    child.expect(pexpect.EOF)
    child.close()

    return '\n'.join(i.strip() for i in child.before.decode('utf-8').split('\n')).lstrip('2')


def expect_wg_revoke(num: str):
    pattern = rf'\s*{num}\) .*?'

    child = pexpect.spawn(WG_SCRIPT_PATH)
    child.expect(r"Select an option \[1\-5\]:")
    child.sendline('3')
    child.expect('Select the existing client you want to revoke')
    try:
        child.expect(pattern, timeout=1)
    except pexpect.TIMEOUT:
        child.close()
        return
    child.sendline(num)
    child.expect(pexpect.EOF)
    out = child.before.decode('utf-8')
    child.close()
    return out


def expect_wg_add(name: str):
    child = pexpect.spawn(WG_SCRIPT_PATH)

    child.expect(r"Select an option \[1\-5\]:")
    child.sendline('1')
    child.expect('Client name:')
    child.sendline(name)
    # default config set
    child.sendline('')
    child.sendline('')

    filename = f'wg0-client-{name}.conf'
    return filename


@bot.on_message(F_COMMAND('/wg list'))
def wg_list(m: Message):
    out = expect_wg_list()
    bot.api.send_message(out, m)


@bot.on_message(F_COMMAND(r'/wg add (\w+)'),
                parse_cb=lambda m: (re.search(r'/wg add ([\w\S]+)', m['text']),))
def wg_add(m: Message, result):
    if not result:
        bot.api.send_message("please provide nickname", m)
        return
    lst = expect_wg_list()
    name = result[1]
    if re.search(rf'\b{name}$', lst):
        bot.api.send_message("this user already exists", m)
        return

    filename = expect_wg_add(name)
    subprocess.run(['qrencode', '-o', 'qrcode.png', filename], shell=True)
    with open(filename, 'rb') as f:
        bot.api.send_document(f, m)
    with open('qrcode.png', 'rb') as f:
        bot.api.send_photo(f, m)


@bot.on_message(F_COMMAND(r'/wg del (\d+)'),
                parse_cb=lambda m: (re.search(r'/wg del (\d+)', m['text']),))
def wg_del(m: Message, result: Match = None):
    if not result:
        bot.api.send_message("Please, provide number", m)
        return
    num = result[0]
    result = expect_wg_revoke(num)
    if not result:
        bot.api.send_message("something went wrong", m)
        return
    bot.api.send_message(f'user with {num} revoked', m)


if __name__ == '__main__':
    if not os.path.exists(WG_SCRIPT_PATH.lstrip('./')):
        print("please, provide correct wg-install script path")
        exit(1)

    bot.run()
