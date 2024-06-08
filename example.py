from tinytg import Bot, M_CHAT, F_COMMAND, F_ALLOW_USERS, M_MSG_ID
bot = Bot()

# admin filter
F_ADMINS = F_ALLOW_USERS(1, 2, 3, 4)

# The rules have a dictionary structure like: `{'key': function(c)}`
# and they process the Update object.
# About fields in this object see documentation:
# https://core.telegram.org/bots/api#update


# invoke rule if a text is anagram (reversed text == base text)
# eg: abba == abba[::-1]
F_IS_ANAGRAM = {"text": lambda c: c.lower().strip() == c.lower().strip()[::-1]}


# you can add multiple handler rules
# its works via AND logic:
# if F_ADMINS = True and command == '/admin' - activate
@bot.on_message(F_ADMINS, F_COMMAND('/admin'))
def admin(m):
    chat = M_CHAT(m)
    bot.api.send_message(chat, "secret admin command!")


@bot.on_message(F_COMMAND('/echo'))
def echo(m: dict):
    # shortcuts for extract chat_id, msg_id
    chat, msg_id = M_CHAT(m), M_MSG_ID(m)
    bot.api.reply_message(chat, msg_id,
                          f"your says: {m['text'].lstrip('/echo ')}")


@bot.on_message(F_IS_ANAGRAM)
def echo(m: dict):
    chat = M_CHAT(m)  # extract chat_id shortcut
    bot.api.send_message(chat, f"your said anagram `{m['text']}`.")


@bot.on_message(F_ADMINS, F_COMMAND('/admin'))
def secret_admin_panel(m: dict):
    chat = M_CHAT(m)  # extract chat_id shortcut
    bot.api.send_message(chat, "wow, hallo admin!")


@bot.on_message(F_COMMAND('/source'))
def send_code(m: dict):
    chat = M_CHAT(m)

    with open('tinytg.py', 'rb') as f:
        bot.api.send_document(f, chat)

    bot.api.send_message(chat, "my source code :-)")


@bot.on_message(F_COMMAND('/img'))
def send_image(m: dict):
    chat = M_CHAT(m)
    with open('img.png', 'rb') as f:
        bot.api.send_photo(f, chat)


@bot.on_message(F_COMMAND('/help'))
def help_msg(m: dict):
    chat = M_CHAT(m)
    help_text = """/help - shows this message
/echo <text> - echo your message
/source - send lib source code as document
/img - send image

also, it answer, if your write anagram
    """

    bot.api.send_message(chat, help_text)


if __name__ == '__main__':
    bot.polling()  # run bot