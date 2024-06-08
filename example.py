from tinytg import Bot, F_COMMAND, F_ALLOW_USERS, Message, F_IS_ATTACHMENT

bot = Bot()

# admin filter
F_ADMINS = F_ALLOW_USERS(1, 2, 3, 4)

# The rules accept Message structure (realize Update event messages
# About fields in this object see documentation:
# https://core.telegram.org/bots/api#update


# invoke rule if a text is anagram (reversed text == base text)
# eg: abba == abba[::-1]
def F_IS_ANAGRAM(m: Message) -> bool:
    return m.text and m.text.lower().strip() == m.text.lower().strip()[::-1]

# or lambda style rule:
# F_IS_ANAGRAM = lambda m: m.text and m.text.lower().strip() == m.text.lower().strip()[::-1]


# you can add multiple handler rules
# its works via AND logic:
# if F_ADMINS = True and command == '/admin' - activate
@bot.on_message(F_ADMINS, F_COMMAND('/admin'))
def admin(m: Message):
    bot.api.send_message(m.from_.id, "secret admin command!")


@bot.on_message(F_COMMAND('/echo'))
def echo(m: Message):
    bot.api.reply_message(m.chat.id, m.message_id, f"your says: {m.text.lstrip('/echo ')}")


@bot.on_message(F_IS_ANAGRAM)
def echo(m: Message):
    bot.api.send_message(m.from_.id, f"your said anagram `{m.text}`.")


@bot.on_message(F_ADMINS, F_COMMAND('/admin'))
def secret_admin_panel(m: Message):
    bot.api.send_message(m.from_.id, "wow, hallo admin!")


@bot.on_message(F_COMMAND('/source'))
def send_code(m: Message):
    with open('tinytg.py', 'rb') as f:
        bot.api.send_document(f, m.from_.id)

    bot.api.send_message(m.from_.id, "my source code :-)")


@bot.on_message(F_COMMAND('/img'))
def send_image(m: Message):
    with open('img.png', 'rb') as f:
        bot.api.send_photo(f, m.from_.id)


@bot.on_message(F_COMMAND('/help'))
def help_msg(m: Message):
    help_text = """/help - shows this message
/echo <text> - echo your message
/source - send lib source code as document
/img - send image

also, it answer, if your write anagram
    """

    bot.api.send_message(m.from_.id, help_text)

@bot.on_message(F_IS_ATTACHMENT)
def handle_attachment(m: Message):
    bot.api.send_message(m.from_.id, f"you send: {m.document.file_name}")

if __name__ == '__main__':
    bot.polling()  # run bot
