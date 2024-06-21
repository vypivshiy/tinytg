"""
Copyright (c) 2024 vypivshiy this code under the UNLICENSE or MIT License.
source: https://github.com/vypivshiy/tinytg

request code under the UNLICENSE or MIT License.
source: https://github.com/sesh/thttp
"""
import gzip, logging, mimetypes, re, ssl, json as json_lib
from base64 import b64encode
from collections import namedtuple
from http.cookiejar import CookieJar
from time import sleep
from typing import Callable, Optional, List, Tuple, BinaryIO, Iterable, Any, TypedDict, Dict, Union, overload
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, Request, build_opener
)
from uuid import uuid4

__VERSION__ = '1.0.0'
Response = namedtuple("Response", "request content json status url headers cookiejar")
NoRedirect = type('NoRedirect', (HTTPRedirectHandler,),
                  {'redirect_request': lambda self, req, fp, code, msg, headers, newurl: None})


# thttp
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
    params, headers, files, method = params or {}, headers or {}, files or {}, method.upper()
    headers = {k.lower(): v for k, v in headers.items()}
    url += f"?{urlencode(params)}" if params else ""

    if method not in {"POST", "PATCH", "PUT", "GET"}:
        raise ValueError("Unknown method type")
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
        headers["content-type"] = f"multipart/form-data; boundary={boundary}"
        headers["content-length"] = str(len(data))

    if basic_auth and len(basic_auth) == 2 and "authorization" not in headers:
        username, password = basic_auth
        auth_value = b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers["authorization"] = f"Basic {auth_value}"

    cookiejar = cookiejar or CookieJar()

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
    boundary, lines = str(uuid4()).encode(), []
    for key, file in files.items():
        file_data = file.read()
        file_data = file_data.encode("utf-8") if isinstance(file_data, str) else file_data
        filename = file.name.encode()
        mime_type = mimetypes.guess_type(filename.decode())[0] or "application/octet-stream"
        lines.extend([
            b"--" + boundary,
            b'Content-Disposition: form-data; name="' + key.encode() + b'"; filename="' + filename + b'"',
            b"Content-Type: " + mime_type.encode(),
            b"",
            file_data,
            *[b"--" + boundary + b"--", b""]
        ])
    return b"\r\n".join(lines), boundary.decode()


def _parse_response(response, ulib_request, cookiejar, is_error=False):
    status, content, headers = (response.code if is_error else response.getcode(), response.read(),
                                {k.lower(): v for k, v in response.info().items()})
    content = gzip.decompress(content) if "gzip" in headers.get("content-encoding", "") else content
    json_content =  json_lib.loads(content) if "application/json" in headers.get("content-type", "").lower() and content else None
    return Response(request=ulib_request, content=content, json=json_content, status=status, url=response.geturl(), 
                    headers=headers, cookiejar=cookiejar)


def read_env(env_file='.env'):
    """simple env files reader"""
    with open(env_file, 'r') as f:
        return {k.strip(): v.strip() for k, v in (line.split('=', 1) for line in f if line.strip() and not line.strip().startswith('#'))}

# telegram event types    
# Used TypedDict + total=False instead of NamedTuple or dataclasses for next reasons:
# 1. avoid a serialization issues
# 2. work with any version of the Bot API without update API class
# 3. get minimal IDE autocomplete
_T_ENTITIES = List[Dict[str, Any]]
Document = TypedDict("Document", {"file_name": str, "mime_type": str, "file_id": str, "file_unique_id": str, "file_size": int}, total=False)
Chat = TypedDict("Chat", { "id": int, "type": str, "first_name": str, "username": Optional[str]}, total=False)
From = TypedDict("From", {"id": int, "is_bot": bool, "first_name": str, "language_code": str, "username": Optional[str]}, total=False)
Message = TypedDict("Message", {"message_id": int, "from": From, "data": int, "chat": Chat, "text": str, "entities": _T_ENTITIES, "document": Document}, total=False)
MessageEvent = TypedDict("MessageEvent", {"update_id": int, "message": Message}, total=False)

# API typing
T_RULE = Callable[[Message], bool]
T_RULES = Tuple[T_RULE, ...]
T_MSG_EVENT = Callable[[Message, ...], None]
T_PARSE_ARGS_CB = Callable[[Message], Tuple[Any, ...]]
T_CALLBACKS = List[Tuple[T_MSG_EVENT, T_RULES, T_PARSE_ARGS_CB]]

# rules shortcuts
F_IS_BOT = lambda m: m['from']['is_bot'] == True
F_IS_USER= lambda m: not F_IS_BOT(m)
F_ALLOW_USERS = lambda *user_ids: lambda m: m['chat']['id'] in user_ids
F_COMMAND = lambda command: lambda m: bool(m['text']) and bool(re.match(command, m['text'])) and m['from']['is_bot'] == False
F_RE = lambda pattern: lambda m: bool(m['text']) and re.search(pattern, m['text'])
F_IS_ATTACHMENT = lambda m: bool(m['document'])
try:
    _lvl = read_env('.env').get('LOG_LEVEL', 'DEBUG')
except Exception as _:
    logging.warning('failed read "LOG_LEVEL" key in .env file. set DEBUG mode')
    _lvl = logging.DEBUG
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', level=_lvl)
logger = logging.getLogger()

class API:
    BASE_URL = 'https://api.telegram.org/bot{}'

    def __init__(self, token: str):
        self._token = token
        self.BASE_URL = self.BASE_URL.format(token)

    def request(self, method, api_method,
                params=None, json=None, data=None, headers=None,
                verify=True, redirect=True, cookiejar=None, basic_auth=None,
                timeout=60, files=None
                ):
        """send request. other non-documented params simular as a requests library)

        :param method: HTTP method
        :param api_method: telegram API method
        """
        url = f'{self.BASE_URL}/{api_method}'
        return request(method, url, json=json, data=data, headers=headers, verify=verify, redirect=redirect,
                       cookiejar=cookiejar, basic_auth=basic_auth, timeout=timeout, files=files, params=params)

    def try_request(self, method, api_method, max_tries=10, **data):
        """send request and try to get response. if is reached max_tries - throw exception"""
        for i in range(max_tries + 1):
            try:
                resp = self.request(method, api_method, **data)
                if (result := resp.json.get('result')) and result:
                    logger.debug('%s %s', resp.status, resp.json)
                return resp
            except Exception as e:
                logger.exception('ERROR: %s %s', api_method, e)
                if i == max_tries:
                    raise e
                sleep(1)
                
    @staticmethod
    def _extract_chat_id(ctx):
        return ctx['chat']['id'] if isinstance(ctx, dict) else ctx
    
    @staticmethod
    def _extract_msg_id(ctx):
        return ctx['message_id'] if isinstance(ctx, dict) else ctx
        
    def request_file(self, api_method: str, files: Dict[str, BinaryIO], **data):
        # this api files sent cannot provide normal data form handling. send it as a params form
        return self.try_request('POST', api_method, files=files, **data)

    def get_updates(self, offset: Optional[int] = None):
        return self.try_request('POST', 'getUpdates', timeout=30, data={'offset': offset}).json['result']

    def send_message(self, text: str, chat_id: Union[Message, int]):
        return self.try_request('POST', 'sendMessage', data={'chat_id': self._extract_chat_id(chat_id), 'text': text})
    
    @overload
    def reply_message(self, text: str, chat_id: int, message_id: int):
        pass

    @overload
    def reply_message(self, text: str, chat_id: Message, message_id: Optional[int]=None):
        pass
    
    def reply_message(self, text: str, chat_id: Union[Message, int], message_id: Optional[int] = None):
        if not message_id and isinstance(chat_id, dict):
            message_id = self._extract_msg_id(chat_id)
        return self.try_request('POST', 'sendMessage', 
                                data={'chat_id': self._extract_chat_id(chat_id), 'text': text, 
                                      'reply_to_message_id': message_id})
    
    def send_document(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendDocument', files={'document': file_ctx}, params={'chat_id': self._extract_chat_id(chat_id)})

    def send_photo(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendPhoto', files={'photo': file_ctx}, params={'chat_id': self._extract_chat_id(chat_id)})

    def send_audio(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendAudio', files={'audio': file_ctx}, params={'chat_id': self._extract_chat_id(chat_id)})

    def send_video(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendVideo', files={'video': file_ctx}, params={'chat_id': self._extract_chat_id(chat_id)})

    def send_voice(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendVoice', files={'voice': file_ctx}, params={'chat_id': self._extract_chat_id(chat_id)})


class Bot:
    def __init__(self, token: str = read_env()["TOKEN"],
                 polling_interval: float =float(read_env().get("POLLING_INTERVAL", '1.0')),
                 global_rules: Iterable[T_RULE] = ()):
        """main bot instance

        :param token: bot token
        :param polling_interval: polling update interval
        :param global_rules: global bot rules (useful for admin filter, for example)
        """
        self._callbacks: T_CALLBACKS = []
        self._api = API(token)
        self.POLLING_INTERVAL = polling_interval
        self._global_rules = global_rules

    @property
    def api(self) -> API: return self._api

    @staticmethod
    def _parse_msg_event(msg: dict) -> MessageEvent:
        return MessageEvent(**msg)

    def run(self):
        """polling alias method"""
        return self.polling()

    def polling(self):
        last_update_id, _ = None, logger.debug('start bot')
        while True:
            try:
                for update in self.api.get_updates(last_update_id):
                    if update.get('message'):
                        event = self._parse_msg_event(update)
                        self._handle_callback(event['message'])
                        last_update_id = event['update_id'] + 1
            except Exception as e:
                logger.exception(e)
            sleep(self.POLLING_INTERVAL)

    @staticmethod
    def _is_rules_passed(m: Message, rules: Iterable[T_RULE]):
        for rule in rules:
            try:
                if not rule(m):
                    return False
            except Exception as e:
                logger.exception('Rule throw exc %s', e)
        return True

    def _handle_callback(self, message: Message) -> None:
        for cb, rules, parse_cb in self._callbacks:
            if self._is_rules_passed(message, self._global_rules) and self._is_rules_passed(message, rules):
                try:
                    args = parse_cb(message)
                except Exception as e:
                    logger.error('failed extract arguments'), logger.exception("%s", e)
                    args = ()
                logger.debug('handling "%s" with args: %s', cb.__name__, args), cb(message, *args)

    def on_message(self, *rules: T_RULE, parse_cb: T_PARSE_ARGS_CB = lambda m: ()):
        """base message event handler decorator

        :param parse_cb: optional parse arguments callback from message
        :param rules: event activate rules
        """
        def decorator(callback: T_MSG_EVENT) -> None:
            self._callbacks.append((callback, rules, parse_cb))
        return decorator
