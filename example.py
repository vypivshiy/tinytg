import re

from tinytg import Bot, F_COMMAND, F_ALLOW_USERS, Message, F_IS_ATTACHMENT, F_RPS_LIMITER, read_env

bot = Bot(token=read_env()["TOKEN"],
          # optional run callback handlers in threads
          # use_threads=True,
          # max_threads=8, limit threads count
          )

# admin filter
# past you telegram id here
F_ADMINS = F_ALLOW_USERS(1, 2, 3, 4)

# The rules accept Message structure (realize Update event messages
# About fields in this object see documentation:
# https://core.telegram.org/bots/api#update


# invoke rule if a text is anagram (reversed text == base text)
# eg: abba == abba[::-1]
def F_IS_ANAGRAM(m: Message) -> bool:
    return m['text'] and m['text'].lower().strip() == m['text'].lower().strip()[::-1]

# or lambda style rule:
# F_IS_ANAGRAM = lambda m: m['text'] and m['text'].lower().strip() == m['text'].lower().strip()[::-1]


# you can add multiple handler rules
# its works via AND logic:
# if F_ADMINS = True and command == '/admin' - activate
@bot.on_message(F_ADMINS,
                F_RPS_LIMITER(1, 10.0),  # rate limiter rule
                F_COMMAND('/admin'))
def admin(m: Message):
    # this lib provide autoextract chat_id from message:
    bot.api.send_message("secret admin command!", m)
    # or you can manually pass chat.id/from.user id keys
    # bot.api.send_message("secret admin command!", chat_id=m['chat']['id'])


# optional parse arguments from message callback
@bot.on_message(F_COMMAND('/echo'),
                parse_cb=lambda m: re.match(r'/echo (.*)', m['text']).groups()
                )
def echo(m: Message, echo_msg: str = None):  # check success parse value
    if echo_msg:
        bot.api.reply_message(f"your says: {echo_msg}", m)
        return
    bot.api.reply_message("please, provide text for /echo command", m)


@bot.on_message(F_IS_ANAGRAM)
def anagram(m: Message):
    bot.api.send_message(f"your said anagram `{m['text']}`.", m)


@bot.on_message(F_ADMINS, F_COMMAND('/admin'))
def secret_admin_panel(m: Message):
    bot.api.send_message("wow, hallo admin!", m)


@bot.on_message(F_COMMAND('/source'))
def send_code(m: Message):
    with open('tinytg.py', 'rb') as f:
        bot.api.send_document(f, m)

    bot.api.send_message("my source code :-)", m)


@bot.on_message(F_COMMAND('/img'))
def send_image(m: Message):
    with open('img.png', 'rb') as f:
        bot.api.send_photo(f, m)


@bot.on_message(F_COMMAND('/help'))
def help_msg(m: Message):
    help_text = """/help - shows this message
/echo <text> - echo your message
/source - send lib source code as document
/img - send image

also, it answer, if your write anagram
    """

    bot.api.send_message(help_text, m)


@bot.on_message(F_IS_ATTACHMENT)
def handle_attachment(m: Message):
    bot.api.send_message(f"you send: {m['document']['file_name']}", m)


# binding commands suggestions
bot.set_command("help", "show help message")
bot.set_command("echo", "echo message")
bot.set_command("img", "send image")
bot.set_command("source", "send my source code :)")

# you can set global rules for avoid duplicate code
# bot.global_rules.append(F_ALLOW_USERS(1,2,3))

if __name__ == '__main__':
    bot.run()
