import unittest
import re
from tinytg import read_env, F_RE, F_COMMAND, F_ALLOW_USERS, F_IS_USER, F_IS_BOT, F_IS_ATTACHMENT

class TestRules(unittest.TestCase):
    def setUp(self):
        self.bot_message = {
            'from': {'is_bot': True},
            'chat': {'id': 1},
            'text': '/start',
            'document': None
        }
        self.user_message = {
            'from': {'is_bot': False},
            'chat': {'id': 2},
            'text': '/help',
            'document': None
        }
        self.user_message_with_doc = {
            'from': {'is_bot': False},
            'chat': {'id': 3},
            'text': '',
            'document': {"file_name": 'file.pdf'}
        }
        self.user_message_with_text = {
            'from': {'is_bot': False},
            'chat': {'id': 4},
            'text': 'hello',
            'document': None
        }

    def test_F_IS_BOT(self):
        self.assertTrue(F_IS_BOT(self.bot_message))
        self.assertFalse(F_IS_BOT(self.user_message))

    def test_F_IS_USER(self):
        self.assertTrue(F_IS_USER(self.user_message))
        self.assertFalse(F_IS_USER(self.bot_message))

    def test_F_ALLOW_USERS(self):
        allow_users_func = F_ALLOW_USERS(2, 3)
        self.assertTrue(allow_users_func(self.user_message))
        self.assertTrue(allow_users_func(self.user_message_with_doc))
        self.assertFalse(allow_users_func(self.bot_message))
        self.assertFalse(allow_users_func(self.user_message_with_text))

    def test_F_COMMAND(self):
        command_func = F_COMMAND(r'^/help')
        self.assertFalse(command_func(self.bot_message))
        self.assertTrue(command_func(self.user_message))
        self.assertFalse(command_func(self.user_message_with_doc))
        self.assertFalse(command_func(self.user_message_with_text))

    def test_F_RE(self):
        re_func = F_RE(r'hello')
        self.assertFalse(re_func(self.bot_message))
        self.assertFalse(re_func(self.user_message))
        self.assertFalse(re_func(self.user_message_with_doc))
        self.assertTrue(re_func(self.user_message_with_text))

    def test_F_IS_ATTACHMENT(self):
        self.assertFalse(F_IS_ATTACHMENT(self.bot_message))
        self.assertFalse(F_IS_ATTACHMENT(self.user_message))
        self.assertTrue(F_IS_ATTACHMENT(self.user_message_with_doc))
        self.assertFalse(F_IS_ATTACHMENT(self.user_message_with_text))


class TestUtils(unittest.TestCase):
    def test_read_env(self):
        ctx = read_env('.env_example')
        self.assertEqual({'TOKEN': 'YOUR_BOT_TOKEN', 'POLLING_INTERVAL': '1', 'LOG_LEVEL': 'DEBUG'}, ctx)



if __name__ == '__main__':
    unittest.main()
