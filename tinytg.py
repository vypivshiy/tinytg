"""
Copyright (c) 2024 vypivshiy
this code under the MIT License.

request code under the UNLICENSE or MIT
author: sesh
source: https://github.com/sesh/thttp
"""
import gzip
import json as json_lib
import logging
import mimetypes
import re
import ssl
from base64 import b64encode
from collections import namedtuple
from http.cookiejar import CookieJar
 
from time import sleep
from typing import Callable, Dict, Optional, List, Tuple, TypeVar, Union, BinaryIO
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, Request, build_opener
)
from uuid import uuid4

T = TypeVar('T')
T_RULE = Dict[str, Callable[[T], bool]]
T_RULES = Tuple[T_RULE, ...]
T_MSG_EVENT = Callable[[Dict[str, T]], None]
T_CALLBACKS = List[Tuple[T_MSG_EVENT, T_RULES]]
Response = namedtuple("Response", "request content json status url headers cookiejar")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, url, params=None, json=None, data=None, headers=None,
            verify=True, redirect=True, cookiejar=None, basic_auth=None,
            timeout=60, files=None):
    """
       Returns a (named)tuple with the following properties:
           - request
           - content
           - json (dict; or None)
           - headers (dict; all lowercase keys)
               - https://stackoverflow.com/questions/5258977/are-http-headers-case-sensitive
           - status
           - url (final url, after any redirects)
           - cookiejar
    """
    params = params or {}
    headers = headers or {}
    files = files or {}
    method = method.upper()
    headers = {k.lower(): v for k, v in headers.items()}

    if method not in {"POST", "PATCH", "PUT", "GET"}:
        raise ValueError("Unknown method type")

    if params:
        url += "?" + urlencode(params)

    if json and data:
        raise ValueError("Cannot provide both json and data parameters")

    if method not in ["POST", "PATCH", "PUT"] and (json or data):
        raise ValueError("Request method must be POST, PATCH or PUT if json or data is provided")

    if files and method != "POST":
        raise ValueError("Request method must be POST when uploading files")

    if json:
        headers["content-type"] = "application/json"
        data = json_lib.dumps(json).encode("utf-8")
    elif data:
        if not isinstance(data, (str, bytes)):
            data = urlencode(data).encode()
        elif isinstance(data, str):
            data = data.encode()
    elif files:
        data, boundary = _encode_multipart_formdata(files)
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        headers["Content-Length"] = str(len(data))

    if basic_auth and len(basic_auth) == 2 and "authorization" not in headers:
        username, password = basic_auth
        auth_value = b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers["authorization"] = f"Basic {auth_value}"

    if cookiejar is None:
        cookiejar = CookieJar()

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    handlers = [HTTPSHandler(context=ctx), HTTPCookieProcessor(cookiejar=cookiejar)]
    if not redirect:
        handlers.append(NoRedirect())

    opener = build_opener(*handlers)
    req = Request(url, data=data, headers=headers, method=method)

    try:
        with opener.open(req, timeout=timeout) as resp:
            return _parse_response(resp, req, cookiejar)
    except HTTPError as e:
        return _parse_response(e, req, cookiejar, is_error=True)


def _encode_multipart_formdata(files):
    boundary = str(uuid4())
    data = b""

    for key, file in files.items():
        file_data = file.read()
        if isinstance(file_data, str):
            file_data = file_data.encode("utf-8")
        filename = file.name
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        data += (
                b"--" + boundary.encode() + b"\r\n"
                b'Content-Disposition: form-data; name="' + key.encode() + b'"; filename="' + filename.encode() + b'"\r\n'
                b"Content-Type: " + mime_type.encode() + b"\r\n\r\n"
                + file_data + b"\r\n"
        )

    data += b"--" + boundary.encode() + b"--\r\n"
    return data, boundary


def _parse_response(response, ulib_request, cookiejar, is_error=False):
    status = response.getcode() if not is_error else response.code
    content = response.read()
    headers = {k.lower(): v for k, v in response.info().items()}

    if "gzip" in headers.get("content-encoding", ""):
        content = gzip.decompress(content)

    json_content = None
    if "application/json" in headers.get("content-type", "").lower() and content:
        json_content = json_lib.loads(content)

    return Response(request=ulib_request, content=content, json=json_content, status=status,
                    url=response.geturl(), headers=headers, cookiejar=cookiejar)


def read_env(env_file='.env'):
    """simple env files reader"""
    with open(env_file, 'r') as f:
        return {k.strip(): v.strip() for k, v in
                (line.split('=', 1) for line in f if line.strip() and not line.strip().startswith('#'))}


def M_CHAT(msg: Dict) -> int:
    """extract chat_id shortcut"""
    return msg['chat']['id']

def M_MSG_ID(msg: Dict) -> int:
    return msg['message_id']

def F_ALLOW_USERS(*user_ids) -> T_RULE:
    """return true if update event contains provided user_ids"""
    return {"chat": lambda c: c['id'] in user_ids}


def F_IS_BOT() -> T_RULE:
    """return true if update event sent by bot"""
    return {'from': lambda c: c['is_bot'] == True}


def F_IS_USER() -> T_RULE:
    """return true if update event sent by user"""
    return {'from': lambda c: c['is_bot'] == False}


def F_COMMAND(command: str, allow_bot: bool = False) -> T_RULE:
    """dummy command wrapper (extract arguments exclude)"""
    return {'text': lambda c: bool(re.match(command, c)),
            'from': lambda c: c['is_bot'] == allow_bot}


def F_RE(pattern: Union[str, re.Pattern[str]]) -> T_RULE:
    """check text by regex pattern"""
    return {'text': lambda c: bool(re.search(pattern, c))}


logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                    level=getattr(logging, read_env().get('LOG_LEVEL', 'DEBUG')))


class API:
    BASE_URL = 'https://api.telegram.org/bot{}'

    def __init__(self, token: str):
        self._token = token
        self.BASE_URL = self.BASE_URL.format(token)

    def api_request(self, method, api_method,
                    params=None, json=None, data=None, headers=None,
                    verify=True, redirect=True, cookiejar=None, basic_auth=None,
                    timeout=60, files=None
                    ):
        url = f'{self.BASE_URL}/{api_method}'
        return request(method, url, json=json, data=data, headers=headers, verify=verify, redirect=redirect,
                       cookiejar=cookiejar, basic_auth=basic_auth, timeout=timeout, files=files, params=params)

    def try_send_api_request(self, method, api_method, max_tries=10, **data):
        for i in range(max_tries + 1):
            try:
                resp = self.api_request(method, api_method, **data)
                if (result := resp.json.get('result')) and result:
                    logging.debug('%s %s', resp.status, resp.json)
                return resp
            except Exception as e:
                logging.exception('ERROR: %s %s', api_method, e)
                if i == max_tries:
                    raise e
                sleep(1)

    def get_updates(self, offset: Optional[int] = None):
        return self.try_send_api_request('POST', 'getUpdates',
                                         timeout=30, data={'offset': offset}).json['result']

    def send_message(self, chat_id: int, text: str):
        return self.try_send_api_request('POST', 'sendMessage', data={'chat_id': chat_id, 'text': text})

    def reply_message(self, chat_id: int, message_id: int, text: str):
        return self.try_send_api_request('POST', 'sendMessage',
                                         data={'chat_id': chat_id, 'text': text, 'reply_to_message_id': message_id})

    def send_document(self, file_ctx: BinaryIO, chat_id: int):
        # this api files sent cannot provide normal data form handling
        # send it as a params form
        return self.try_send_api_request(
            'POST', 'sendDocument', files={'document': file_ctx}, params={'chat_id': chat_id})

    def send_photo(self, file_ctx: BinaryIO, chat_id: int):
        return self.try_send_api_request(
            'POST', 'sendPhoto', files={'photo': file_ctx}, params={'chat_id': chat_id})

    def send_audio(self, file_ctx: BinaryIO, chat_id: int):
        return self.try_send_api_request(
            'POST', 'sendAudio', files={'audio': file_ctx}, params={'chat_id': chat_id})

    def send_video(self, file_ctx: BinaryIO, chat_id: int):
        return self.try_send_api_request(
            'POST', 'sendVideo', files={'video': file_ctx}, params={'chat_id': chat_id})

    def send_voice(self, file_ctx: BinaryIO, chat_id: int):
        return self.try_send_api_request(
            'POST', 'sendVoice', files={'voice': file_ctx}, params={'chat_id': chat_id})


class Bot:
    POLLING_INTERVAL = 1.0

    def __init__(self, token: str = read_env()["TOKEN"],
                 polling_interval=read_env().get("POLLING_INTERVAL", '1.0')):
        self._callbacks: T_CALLBACKS = []
        self._api = API(token)
        self.POLLING_INTERVAL = float(polling_interval)

    @property
    def api(self) -> API:
        return self._api

    def polling(self):
        last_update_id = None
        while True:
            try:
                for update in self.api.get_updates(last_update_id):
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
