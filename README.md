# tinytg

Minimal telegram botapi implementation with ZERO dependencies

# Why

Telegram bot api is one of the popular and simple solutions as an interface for automating various tasks.

**This project is not intended to solve all use cases that can be achieved with aiogram, telegrinder, pyTelegramBotAPI 
and other telegram bot api wrappers.**

**The intent is to provide a lightweight tool that simplifies some of the most common use cases for developers.**

# Features

- Module size have ~300 lines of code
- ZERO dependencies
- http request logic by [thttp](https://github.com/sesh/thttp) (standard urllib wrapper)
- Sending/Reply messages
- Sending a document, photo, audio, video, voice files
- handle message events by decorator
- Primitive .env file reader

# install

```sh
wget https://raw.githubusercontent.com/vypivshiy/tinytg/main/tinytg.py
```

or via curl:

```sh
curl https://raw.githubusercontent.com/vypivshiy/tinytg/main/tinytg.py > tinytg.py
```

# hello-world

```python
from tinytg import Bot, Message, read_env

bot = Bot(read_env()['TOKEN'])
# or pass via argument (not recommended
# bot = Bot(token="MY-BOT-TOKEN")


@bot.on_message()
def hello(m: Message):
    bot.api.send_message(m.chat.id, "HELLO, WORLD!")

bot.polling()
```

# Usage
- create `.env` file in project directory (see [env file example](.env_example)):

```env
TOKEN=YOUR_BOT_TOKEN
POLLING_INTERVAL=1
# DEBUG, ERROR, INFO, ....
LOG_LEVEL=DEBUG
```

- See [example](example.py) code how-to usage
