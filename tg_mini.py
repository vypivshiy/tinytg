"""
The MIT License (MIT)

Copyright (c) 2024 vypivshiy

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
"""
import json
import logging
import mimetypes
import re
from pathlib import Path
from time import sleep
from typing import Callable, Dict, Optional, List, Tuple, TypeVar, Union
from urllib import request, parse as u_parse
from uuid import uuid4

T = TypeVar('T')
T_RULE = Dict[str, Callable[[T], bool]]
T_RULES = Tuple[T_RULE, ...]
T_MSG_EVENT = Callable[[Dict[str, T]], None]
T_CALLBACKS = List[Tuple[T_MSG_EVENT, T_RULES]]

# Utils
def read_env(env_file='.env'):
    with open(env_file, 'r') as f:
        return {k.strip(): v.strip() for k, v in (line.split('=', 1) for line in f if line and not line.startswith('#'))}

def create_multipart_body(fields, file_content: bytes, file_name: str, file_field_name: str):
    boundary = f'----WebKitFormBoundary{uuid4().hex}'
    lines = [f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n' for name, value in fields.items()]
    file_type = mimetypes.guess_type(file_name)[0] or 'application/octet-stream'
    lines.extend([
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field_name}"; filename="{file_name}"\r\nContent-Type: {file_type}\r\n\r\n',
        file_content.decode('ISO-8859-1'),
        f'\r\n--{boundary}--\r\n'
    ])
    return '\r\n'.join(lines).encode(), f'multipart/form-data; boundary={boundary}'

def M_CHAT(msg: dict) -> int:
    return msg['chat']['id']

# Dummy filter shortcuts
def F_ALLOW_USERS(*user_ids) -> T_RULE:
    return {"chat": lambda c: c['id'] in user_ids}

def F_IS_BOT() -> T_RULE:
    return {'from': lambda c: c['is_bot'] == True}

def F_IS_USER() -> T_RULE:
    return {'from': lambda c: c['is_bot'] == False}

def F_COMMAND(command: str) -> T_RULE:
    return {'text': lambda c: bool(re.match(command, c)),
            'from': lambda c: c['is_bot'] == False}

def F_RE(pattern: Union[str, re.Pattern[str]]) -> T_RULE:
    return {'text': lambda c: bool(re.search(pattern, c))}

# Read environment variables
_ENV = read_env()
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', level=logging.DEBUG)

class API:
    BASE_URL = 'https://api.telegram.org/bot{}'

    def __init__(self, token: str):
        self._token = token
        self.BASE_URL = self.BASE_URL.format(token)

    def request(self, method: str, **data):
        url = f'{self.BASE_URL}/{method}'
        data = u_parse.urlencode(data).encode() if data else {}
        req = request.Request(url, data=data, method='POST')
        with request.urlopen(req) as response:
            resp = json.loads(response.read().decode())
            if resp['result']:
                logging.debug('[%s] %s', response.code, resp)
            return resp

    def request_raw_upload(self, file: bytes, file_name: str, chat_id: int, *, method: str = 'sendDocument', file_field_name: str = "document", **data):
        body, header = create_multipart_body({'chat_id': chat_id, **data}, file, file_name, file_field_name)
        req = request.Request(f"{self.BASE_URL}/{method}", data=body, method='POST', headers={'Content-Type': header})
        with request.urlopen(req) as f:
            response = f.read().decode()
            return json.loads(response)

    def try_send_request(self, method: str, max_tries=10, **data):
        for i in range(max_tries + 1):
            try:
                return self.request(method, **data)
            except Exception as e:
                logging.error('ERROR: %s', e)
                if i == max_tries:
                    raise e
                sleep(1)

    def get_updates(self, offset: Optional[int] = None):
        return self.try_send_request('getUpdates', timeout=30, offset=offset)['result']

    def send_message(self, chat_id: int, text: str):
        return self.try_send_request('sendMessage', chat_id=chat_id, text=text)

    def send_document(self, file: str, chat_id: int, **data):
        file_path = Path(file)
        return self.request_raw_upload(file_path.read_bytes(), file_path.name, chat_id, method='sendDocument', file_field_name='document', **data)

class Bot:
    POLLING_INTERVAL = float(_ENV.get("POLLING_INTERVAL", '1.0'))

    def __init__(self, token: str = _ENV["TOKEN"]):
        self._callbacks: T_CALLBACKS = []
        self._api = API(token)

    @property
    def api(self) -> API:
        return self._api

    def polling(self):
        last_update_id = None
        while True:
            try:
                updates = self.api.get_updates(last_update_id)
                for update in updates:
                    message = update.get('message')
                    if not message:
                        continue
                    self._handle_callback(message)
                    last_update_id = update['update_id'] + 1
            except Exception as e:
                logging.exception(e)
            sleep(self.POLLING_INTERVAL)

    def _handle_callback(self, message) -> None:
        for cb, rules in self._callbacks:
            if all(all(cmp(message.get(key)) for key, cmp in rule.items()) for rule in rules):
                cb(message)

    def on_message(self, *rules: T_RULE):
        def decorator(callback: T_MSG_EVENT) -> None:
            self._callbacks.append((callback, rules))
        return decorator
