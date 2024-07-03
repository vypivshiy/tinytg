# tinytg

Minimal telegram botapi implementation with ZERO dependencies

# Why

Telegram bot api is one of the popular and simple solutions as an interface for automating various tasks.

**This project is not intended to solve all use cases that can be achieved with aiogram, telegrinder, pyTelegramBotAPI 
and other telegram bot api wrappers and frameworks.**

**The intent is to provide a lightweight tool that simplifies some of the most common use cases for developers.**

# Features

- ZERO dependencies
- python 3.8+ support
- simple, primitive: module have one file with less than 1000 lines of code (docstrings and comments include)
- http requests work on standard urllib (ty [thttp](https://github.com/sesh/thttp) project for wrapper <3)
- minimal build-in shortcuts: 
  - Sending/Reply messages
  - Sending a document, photo, audio, video, voice files
  - [binding commands](https://core.telegram.org/bots/api#setmycommands)
- rules (filters) for handling message events
  - F_IS_BOT - activate if is bot send message
  - F_IS_USER - activate if is user send message
  - F_ALLOW_USERS - activate, if is allowed user ids send message (for create admin/whitelist feature)
  - F_COMMAND - check text message by startswith pattern
  - F_RE - check text message by regex
  - F_IS_ATTACHMENT - check sending attachment
  - F_RPS_LIMITER - simple request-per-second limiter
  - or create custom rules by simple API function
- simple background tasks runner
- thread-mode run callbacks (experimental)
- parse arguments from message event
- handle message events by decorator
- primitive .env file reader

# install

that is the pip? just copy or download single file, dude

```sh
wget https://raw.githubusercontent.com/vypivshiy/tinytg/main/tinytg.py -O tinytg.py
```

via curl:

```sh
curl https://raw.githubusercontent.com/vypivshiy/tinytg/main/tinytg.py > tinytg.py
```

# Usage
- create `.env` file in project directory (see [env file example](.env_example)):

```env
TOKEN=YOUR_BOT_TOKEN
# any secret config files
ADMIN_IDS=1000,2000
# ...
```

```python
from tinytg import Bot, Message, load_dotenv, F_IS_USER
import os

load_dotenv()
bot = Bot(os.getenv('TOKEN'))
# or pass via argument (not recommended)
# bot = Bot(token="MY-BOT-TOKEN")


@bot.on_message(F_IS_USER)
def hello(m: Message):
    bot.api.send_message("HELLO, WORLD!", m)


bot.run()
```

- See [examples](examples) code how-to usage
