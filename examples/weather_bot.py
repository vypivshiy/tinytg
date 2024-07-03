# weather-bot
#
# just a mainstream weather bot. like in uninteresting tutorials, yes
import os
import re

from tinytg import request, Bot, F_COMMAND, Message

# get token from https://openweathermap.org
WEATHER_API_KEY = os.getenv('WEATHER_API_KEY')
bot = Bot(token=os.getenv('TOKEN'))


def get_weather(city: str):
    """dummy openweather API implementation usage build-in request"""
    # NOTE: i don't remember: its actual and correct API method. Check documentation before run
    # this example

    # not required installation requests, httpx or any libs for this simple case
    url = f'https://api.openweathermap.org/data/2.5/weather?q={city}&appid={WEATHER_API_KEY}&units=metric'
    response = request('GET', url).json
    if response['cod'] != 200:
        return "City not found or something API error"

    desc = response['weather'][0]['description']
    temp = response['main']['temp']
    return f'Weather in {city}: {desc}, Temperature: {temp}°C'


@bot.on_message(F_COMMAND('/start'))
def start(m: Message):
    bot.api.send_message('usage: /weather <city> to get the weather information.', m)


@bot.on_message(F_COMMAND(r'/weather (\w+)'),
                parse_cb=lambda m: (
                        re.search(r'/weather (\w+)', m['text']),
                ))
def weather(m: Message, city: re.Match = None):
    if not city:
        return bot.api.send_message('No city provided', m)

    city = city[0]
    response = get_weather(city)
    bot.api.send_message(response, m)


if __name__ == '__main__':
    bot.run()
