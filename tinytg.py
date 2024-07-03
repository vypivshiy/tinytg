"""
Copyright (c) 2024 vypivshiy this code under the UNLICENSE or MIT License.
source: https://github.com/vypivshiy/tinytg

request code under the UNLICENSE or MIT License.
source: https://github.com/sesh/thttp
"""
import datetime
import gzip, logging, mimetypes, re, ssl, json as json_lib
from base64 import b64encode
from collections import namedtuple
from functools import wraps
from http.cookiejar import CookieJar
from time import sleep, time
from typing import Callable, Optional, List, Tuple, BinaryIO, Iterable, Any, TypedDict, Dict, Union, overload, Pattern
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, Request, build_opener
)
from uuid import uuid4
from threading import Thread, RLock, enumerate as threads_enumerate
from collections import deque

__VERSION__ = '1.4.0'
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

    if method not in {"POST", "PATCH", "PUT", "GET", "HEAD"}:
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
    json_content = json_lib.loads(content) if "application/json" in headers.get("content-type",
                                                                                "").lower() and content else None
    return Response(request=ulib_request, content=content, json=json_content, status=status, url=response.geturl(),
                    headers=headers, cookiejar=cookiejar)


def read_env(env_file='.env') -> Dict[str, str]:
    """simple env files reader"""
    # note: this very simple form and not coverage several cases
    # 1. ignore comments (# )
    # 2. split by '=' and strip whitespaces
    with open(env_file, 'r') as f:
        return {k.strip(): v.strip() for k, v in
                (line.split('=', 1) for line in f if line.strip() and not line.strip().startswith('#'))}


def load_dotenv(env_file='.env') -> None:
    """load env file to os.environ"""
    import os
    new_env = read_env(env_file)
    os.environ.update(new_env)

# Used TypedDict + total=False instead of NamedTuple or dataclasses for next reasons:
# 1. avoid a serialization and validation issues (receive non message events or botapi update broke it)
# 2. work with any version of the Bot API without update API types
# 3. get minimal autocomplete support in IDE
# telegram event types
_T_ENTITIES = List[Dict[str, Any]]
Document = TypedDict("Document",
                     {"file_name": str, "mime_type": str, "file_id": str, "file_unique_id": str, "file_size": int},
                     total=False)
Chat = TypedDict("Chat", {"id": int, "type": str, "first_name": str, "username": Optional[str]}, total=False)
From = TypedDict("From",
                 {"id": int, "is_bot": bool, "first_name": str, "language_code": str, "username": Optional[str]},
                 total=False)
Message = TypedDict("Message",
                    {"message_id": int, "from": From, "data": int, "chat": Chat, "text": str, "entities": _T_ENTITIES,
                     "document": Document}, total=False)
MessageEvent = TypedDict("MessageEvent", {"update_id": int, "message": Message}, total=False)

# tinytg API typing
T_RULE = Callable[[Message], bool]
T_RULES = Tuple[T_RULE, ...]
T_MSG_EVENT = Callable[[Message, ...], None]
T_PARSE_ARGS_CB = Callable[[Message], Tuple[Any, ...]]
T_CALLBACKS = List[Tuple[T_MSG_EVENT, T_RULES, T_PARSE_ARGS_CB]]
T_BG_INTERVAL = Union[float, datetime.datetime, datetime.timedelta]

# build-in common rules shortcuts for handle message events
def F_IS_BOT(m: Message) -> bool:
    """return true if message sent by bot"""
    return m["from"]["is_bot"] is True


def F_IS_USER(m: Message) -> bool:
    """return true if message sent by user"""
    return not F_IS_BOT(m)


def F_ALLOW_USERS(*user_ids: int) -> T_RULE:
    """return true if message send from chat_id or user_id from user_ids sequence

    eg:

    >>> F_ALLOW_USERS(1,2,3)({"chat": {"id": 1}})
    True
    >>> F_ALLOW_USERS(1,2,3)({"chat": {"id": 4}})
    False
    """

    def wrapper(m: Message) -> bool:
        return m["chat"]["id"] in user_ids

    return wrapper


def F_COMMAND(pattern: Union[str, Pattern[str]], allow_bot: bool = False) -> T_RULE:
    """match message text by re.match rule:

    :param pattern: regex pattern
    :param allow_bot: handle rule from bot messages (default False)
    
    eg:
        >>> F_COMMAND("/start")({"text": "/start", "from": {"is_bot": True}})
        True
        >>> F_COMMAND("ok, /start")({"text": "/start", "from": {"is_bot": True}})
        False
        >>> F_COMMAND("/start")({"text": "/start", "from": {"is_bot": False}})
        False
    """

    def wrapper(m: Message) -> bool:
        # check if text is not none
        expr = bool(m.get("text", None)) and bool(re.match(pattern, m['text']))
        return expr if expr and allow_bot else expr and not F_IS_BOT(m)

    return wrapper


def F_RE(pattern: Union[str, Pattern[str]], allow_bot: bool = False) -> T_RULE:
    """match message text by re.search rule:

    :param pattern: regex pattern
    :param allow_bot: handle rule from bot messages (default False)

        eg:
            >>> F_RE("/start")({"text": "/start", "from": {"is_bot": True}})
            True
            >>> F_RE("ok, /start")({"text": "/start", "from": {"is_bot": True}})
            True
            >>> F_RE("/start")({"text": "/start", "from": {"is_bot": False}})
            True
    """

    def wrapper(m: Message) -> bool:
        expr = bool(m['text']) and bool(re.search(pattern, m['text']))
        return expr if expr and allow_bot else expr and not F_IS_BOT(m)

    return wrapper


def F_IS_ATTACHMENT(m: Message) -> bool:
    """return True if message contains attachment"""
    # MAYBE not contains this key
    return bool(m.get('document', None))


def F_RPS_LIMITER(count: int, delay: float) -> T_RULE:
    """RPS LIMITER rule. return False if limit is reached and ignore handle command

    :param delay: wait seconds delay
    :param count: object
    """
    rps_check_cb = rps_check(count, delay)

    def is_rps_lock() -> bool:
        state, rps_delay = rps_check_cb()
        if state:
            logger.info(f"RPS limit, wait, {rps_delay}")
            return False
        return True

    def wrapper(_: Message) -> bool:
        return is_rps_lock()

    return wrapper


try:
    _lvl = read_env('.env').get('LOG_LEVEL', 'DEBUG')
    _lvl = getattr(logging, _lvl)
except Exception as _:
    logging.warning('failed read "LOG_LEVEL" key from .env file. set DEBUG mode')
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
        """send a telegram API request. other non-documented params simular as a requests library)

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
    def reply_message(self, text: str, chat_id: Message, message_id: Optional[int] = None):
        pass

    def reply_message(self, text: str, chat_id: Union[Message, int], message_id: Optional[int] = None):
        if not message_id and isinstance(chat_id, dict):
            message_id = self._extract_msg_id(chat_id)
        return self.try_request('POST', 'sendMessage',
                                data={'chat_id': self._extract_chat_id(chat_id), 'text': text,
                                      'reply_to_message_id': message_id})

    def send_document(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendDocument', files={'document': file_ctx},
                                 params={'chat_id': self._extract_chat_id(chat_id)})

    def send_photo(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendPhoto', files={'photo': file_ctx},
                                 params={'chat_id': self._extract_chat_id(chat_id)})

    def send_audio(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendAudio', files={'audio': file_ctx},
                                 params={'chat_id': self._extract_chat_id(chat_id)})

    def send_video(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendVideo', files={'video': file_ctx},
                                 params={'chat_id': self._extract_chat_id(chat_id)})

    def send_voice(self, file_ctx: BinaryIO, chat_id: Union[Message, int]):
        return self.request_file('sendVoice', files={'voice': file_ctx},
                                 params={'chat_id': self._extract_chat_id(chat_id)})


def rps_check(count: int, delay: float) -> Callable[[], Tuple[bool, float]]:
    """Rate limiter that ensures a maximum number of `count` requests within `delay` seconds.

    Returns False if request is allowed, True if it is denied.

    usage:

    rate_limiter = rps_check(5, 1)

    for _ in range(10):
        if rate_limiter():
            print("Request denied")
        else:
            print("Request allowed")
        time.sleep(0.1)  # Simulating time delay between requests
    """
    times = deque()

    def is_rate_limit() -> Tuple[bool, float]:
        current_time = time()
        # clear timestamps
        while times and current_time - times[0] >= delay:
            times.popleft()
        if len(times) < count:
            times.append(current_time)
            return False, 0
        return True, current_time - times[0]

    return is_rate_limit


class BaseBotApiHandler:
    def __init__(self,
                 api: API,
                 global_rules: Iterable[T_RULE] = (),
                 update_interval: float = .5,
                 **kwargs):
        self._update_interval = update_interval
        self._api = api
        self._global_rules = global_rules

        self._rules: List[T_RULE] = []
        self._callbacks: T_CALLBACKS = []
        # setCommands pre execute payload
        self._commands = {"commands": []}

    @property
    def api(self):
        return self._api

    @property
    def global_rules(self):
        return self._global_rules

    @staticmethod
    def _parse_msg_event(msg: dict) -> MessageEvent:
        return MessageEvent(**msg)

    def polling(self):
        raise NotImplementedError

    def _bind_commands(self):
        if self._commands['commands']:
            self.api.request("POST", "setMyCommands", json=self._commands)

    @staticmethod
    def _check_rules(m: Message, rules: Iterable[T_RULE]) -> bool:
        # rules works as AND logic
        for rule in rules:
            try:
                if not rule(m):
                    return False
            except Exception as e:
                logger.exception('Rule throw exc %s', e)
                return False
        return True

    def _handle_callback(self, message: Message) -> None:
        for cb, rules, parse_cb in self._callbacks:
            if self._check_rules(message, self._global_rules) and self._check_rules(message, rules):
                try:
                    args = parse_cb(message)
                except Exception as e:
                    logger.error('failed extract arguments'), logger.exception("%s", e)
                    args = ()
                logger.debug('handling "%s" with args: %s', cb.__name__, args), cb(message, *args)

    def register_msg_event(self, callback: T_MSG_EVENT, *rules: T_RULE, parse_cb: T_PARSE_ARGS_CB = lambda m: ()
                           ) -> None:
        self._callbacks.append((callback, rules, parse_cb))

    def on_message(self, *rules: T_RULE, parse_cb: T_PARSE_ARGS_CB = lambda m: ()):
        """base message event handler decorator

        :param parse_cb: optional parse arguments callback from message
        :param rules: event activate rules
        """

        def decorator(callback: T_MSG_EVENT) -> None:
            self.register_msg_event(callback, *rules, parse_cb=parse_cb)

        return decorator

    def set_command(self, command: str, description: str):
        """bind commands in bot"""
        self._commands["commands"].append({"command": command, "description": description})


class ThreadBotApiHandler(BaseBotApiHandler):
    def __init__(self, api: API, max_threads: int, **kwargs):
        super().__init__(api, **kwargs)
        self._max_threads = max_threads
        self._lock = RLock()

    @staticmethod
    def active_threads() -> int:
        # background tasks running in daemon mode - ignore this
        return len([t for t in threads_enumerate() if not t.daemon])

    def _r_lock_threads(self):
        with self._lock:
            while self.active_threads() >= self._max_threads:
                self._lock.release()
                sleep(0.3)
                self._lock.acquire()

    def polling(self):
        last_update_id, _ = None, self._bind_commands()
        while True:
            try:
                sleep(self._update_interval)
                updates = self.api.get_updates(last_update_id)
                for update in updates:
                    if update.get('message'):
                        event = self._parse_msg_event(update)
                        self._r_lock_threads()
                        Thread(target=self._handle_callback, args=(event['message'],)).start()
                        last_update_id = event['update_id'] + 1
            except Exception as e:
                logger.exception(e)


class BotApiHandler(BaseBotApiHandler):
    def polling(self):
        last_update_id, _ = None, self._bind_commands()
        while True:
            try:
                sleep(self._update_interval)
                for update in self.api.get_updates(last_update_id):
                    if update.get('message'):
                        event = self._parse_msg_event(update)
                        self._handle_callback(event['message'])
                        last_update_id = event['update_id'] + 1
            except Exception as e:
                logger.exception(e)


def background(interval: T_BG_INTERVAL):
    if isinstance(interval, float) or isinstance(interval, int):
        interval = datetime.timedelta(seconds=interval)
    elif isinstance(interval, datetime.datetime) or isinstance(interval, datetime.timedelta):
        interval = interval
    else:
        msg = f"Interval must be float, int, datetime, or timedelta, not {type(interval)}"
        raise TypeError(msg)

    if interval.seconds <= 0:
        raise TypeError("interval must be bigger than 0")

    def decorator(func: Callable[[], None]):
        @wraps(func)
        def wrapper():
            def background_task():
                next_run = datetime.datetime.now() + interval
                while True:
                    sleep(1)
                    if datetime.datetime.now() >= next_run:
                        try:
                            logging.debug(f"Starting task {func.__name__}")
                            func()
                            logging.debug(f"Task {func.__name__} completed")
                        except Exception as e:
                            logging.error(f"Task {func.__name__} encountered an error: {e}")
                        next_run += interval
            task_thread = Thread(target=background_task, daemon=True)
            task_thread.start()
            return task_thread
        return wrapper

    return decorator


class Bot:
    def __init__(self,
                 token: str,
                 polling_interval: float = .5,
                 global_rules: Iterable[T_RULE] = (),
                 use_threads: bool = False,
                 max_threads: int = 16
                 ):
        """main bot instance


        :param token: bot token
        :param polling_interval: polling update interval
        :param global_rules: global bot rules (useful for admin filter, for example)
        :param use_threads: EXPERIMENTAL: run caught handlers in threads. default false
        :param max_threads: max threads count
        """
        self._bot_handler: BaseBotApiHandler
        if use_threads:
            self._bot_handler = ThreadBotApiHandler(
                api=API(token),
                max_threads=max_threads,
                global_rules=global_rules,
                update_interval=polling_interval
            )
        else:
            self._bot_handler = BotApiHandler(api=API(token),
                                              global_rules=global_rules,
                                              update_interval=polling_interval)
        self._api = API(token)
        self._commands = {"commands": []}  # for setCommands execute
        self._bg_tasks: List[Thread] = []

    @property
    def api(self) -> API:
        return self._bot_handler.api

    @property
    def background_tasks(self) -> List[Thread]:
        return self._bg_tasks

    def run(self):
        """polling alias method"""
        bot_info = self.api.request("GET", "getMe")
        if bot_info.status != 200:
            msg = f"API returned {bot_info.status}: {bot_info.content.decode()}"
            raise ConnectionError(msg)
        bot_info = bot_info.json['result']
        log_msg = f"{bot_info['first_name']}, id: {bot_info['id']}, username: @{bot_info['username']}"
        logger.debug('start bot %s', log_msg)
        return self._bot_handler.polling()

    def set_command(self, cmd: str, description: str):
        """call setCommand method before start polling"""
        self._bot_handler.set_command(cmd, description)

    def on_message(self, *rules: T_RULE, parse_cb: T_PARSE_ARGS_CB = lambda m: ()):
        """register telegram message event. invoke by passed rules and parse message by parse_cb argument"""
        def decorator(cb: T_MSG_EVENT):
            self._bot_handler.register_msg_event(cb, *rules, parse_cb=parse_cb)
        return decorator

    def register_message_event(self, cb: T_MSG_EVENT, *rules: T_RULE, parse_cb: T_PARSE_ARGS_CB = lambda m: ()):
        self._bot_handler.register_msg_event(cb, *rules, parse_cb=parse_cb)

    def on_background(self, interval: T_BG_INTERVAL):
        """register background daemon task. func should be not accept any arguments"""
        def decorator(func):
            task = background(interval)(func)()
            self._bg_tasks.append(task)
            return task
        return decorator

    def register_background_task(self, func: Callable[[], None], interval: T_BG_INTERVAL):
        task = background(interval)(func)()
        self._bg_tasks.append(task)
        return task
