# tg-mini
minimal telegram botapi lib with zero dependencies 

# Why

The Telegram Bot API is one of the popular ways to implement interfaces for various automation tasks.

Frameworks are a good tool for writing bots, but when **the task is small and simple**, their functionality is too excessive. 
Or sometimes they are often long or difficult to understand 🤪.

# install

```sh
wget https://raw.githubusercontent.com/vypivshiy/tg-mini/main/tg_mini.py
# or via curl
curl wget https://raw.githubusercontent.com/vypivshiy/tg-mini/main/tg_mini.py
```


# Features

- Module size ~150 lines of code
- No dependencies, requests are sent using urllib
- Sending messages
- Sending documents
- Primitive message handling rules

# usage

1. create env file or pass bot token into a code (not recommended):

```env
# your bot token
TOKEN=YOUR_BOT_TOKEN
# update polling interval
POLLING_INTERVAL=1 
```

2. simple code:
   
```python
from tg_mini import Bot, M_CHAT, F_COMMAND, F_ALLOW_USERS


bot = Bot()

# admin filter
F_ADMINS = F_ALLOW_USERS(1, 2, 3, 539024411)  


@bot.on_message(F_COMMAND('/echo'))
def echo(m: dict):
    chat = M_CHAT(m)  # extract chat_id shortcut
    bot.api.send_message(chat, f"your says: {m['text'].lstrip('/echo ')}")


@bot.on_message(F_ADMINS, F_COMMAND('/admin'))
def secret_admin_panel(m: dict):
    chat = M_CHAT(m)  # extract chat_id shortcut
    bot.api.send_message(chat, "wow, hallo admin!")


@bot.on_message(F_COMMAND('/source'))
def send_code(m: dict):
    chat = M_CHAT(m)  # extract chat_id shortcut
    bot.api.send_document('tg_mini.py', chat)
    bot.api.send_message(chat, "my source code :-)")
    
    
bot.polling()  # run bot
```

3. custom rules

The rules have a dictionary structure like: `{'key': function(c)}` and they process the [Update](https://core.telegram.org/bots/api#update) object.

```python
from tg_mini import Bot, M_CHAT, F_COMMAND


bot = Bot()

# text should be less than 150
TEXT_LEN_RULE = {'text': lambda c: len(c) < 150}


@bot.on_message(F_COMMAND('/echo'),
                TEXT_LEN_RULE)
def echo(m: dict):
    chat = M_CHAT(m)  # extract chat_id shortcut
    bot.api.send_message(chat, f"your says: {m['text'].lstrip('/echo ')}")


bot.polling()
```
