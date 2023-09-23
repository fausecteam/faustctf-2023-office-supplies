#!/usr/bin/env python3

from ctf_gameserver import checkerlib
import pwn
import logging
import secrets
import re

import utils
import random

pwn.context.log_level = 'warn'
pwn.context.timeout = 5


class InvalidInterface(Exception):
    def __init__(self, expected, actual, message="Unexpected response"):
        super().__init__(f'{message} "{expected}" != "{actual}"')


def interface_assert(expected, actual):
    if expected != actual:
        raise InvalidInterface(expected, actual)


class DbChecker(checkerlib.BaseChecker):
    def connection(self):
        try:
            return pwn.remote(self.ip, 1337)
        except pwn.PwnlibException:
            raise ConnectionRefusedError()

    def read_lines(self, S, num):
        return '\n'.join([S.recvlineS() for x in range(num)])

    def register(self, S, payment):
        # Check that we are in the login menu
        response = S.recvuntil(b'> ')
        interface_assert(b'1. Register\n2. Login\n> ', response)

        username = secrets.token_hex(secrets.randbelow(10) + 10)
        password = secrets.token_hex(secrets.randbelow(10) + 10)

        logging.info(f'Registering user {username} with password {password} and payment {payment}')
        S.sendline(b"1")
        S.recvuntil(b"Username: ")
        S.sendline(username.encode())
        S.recvuntil(b"Password: ")
        S.sendline(password.encode())
        S.recvuntil(b"Payment Info: ")
        S.sendline(payment.encode())

        response = self.read_lines(S, 4)
        expected = f"\n\nHello {username}. Welcome to the future of marketplace logistics.\n\nYour purchases will be automatically deducted from your payment info {payment}. Your money is safe with our blazingly fast and memory safe application\n\n\n"

        interface_assert(expected, response)

        return (username, password)

    def login(self, S, username, password):
        # Check that we are in the login menu
        response = S.recvuntil(b'> ')
        interface_assert(b'1. Register\n2. Login\n> ', response)

        logging.info(f'Logging in as user {username} with password {password}')
        S.sendline(b"2")
        S.recvuntil(b"Username: ")
        S.sendline(username.encode())
        S.recvuntil(b"Password: ")
        S.sendline(password.encode())

        response = self.read_lines(S, 4)
        match = re.match(f'^\n\nHello {username}\\. Welcome to the future of marketplace logistics\\.\n\nYour purchases will be automatically deducted from your payment info (.+)\\. Your money is safe with our blazingly fast and memory safe application\n\n\n$', response)
        if not match:
            raise InvalidInterface(match, response, message="Couldn't find match in payment info")

        return match.group(1)

    def place_flag(self, tick):
        S = self.connection()
        flag = checkerlib.get_flag(tick)
        logging.info(f'Placing flag {flag}')
        try:
            username, password = self.register(S, flag)
            checkerlib.store_state(str(tick), (username, password))
        except InvalidInterface as e:
            logging.error(f"Failure while placing flag: {e}")
            return checkerlib.CheckResult.FAULTY
        finally:
            S.close()

        return checkerlib.CheckResult.OK

    def random_payment(self):
        return secrets.token_hex(secrets.randbelow(10) + 8)

    def check_menu(self, S):
        response = S.recvuntil(b'> ')
        interface_assert(b"1. List Products\n2. Buy Product\n3. Sell Product\n4. Edit Product\n5. Report a Bug\n6. Hear inspiring stories from our users\n7. Exit\n> ", response.lstrip())

    def check_create(self, S):
        productname = secrets.token_hex(secrets.randbelow(10) + 8)
        cost = secrets.randbelow(1337)
        blueprint = secrets.token_hex(secrets.randbelow(64)*128 + 128)

        self.check_menu(S)
        S.sendline(b"3")
        S.recvuntil(b"Name: ")
        S.sendline(productname.encode())
        S.recvuntil(b"Cost: ")
        S.sendline(str(cost).encode())
        S.recvuntil(b"Blueprint Length (hex): ")
        S.sendline(str(len(blueprint)).encode())
        S.recvuntil(b"Blueprint Data (hex): ")
        S.sendline(blueprint.encode())
        interface_assert("Product added\n", S.recvlineS())
        return productname, blueprint

    def check_list(self, S):
        logging.info("Listing products...")
        self.check_menu(S)
        S.sendline(b"1")
        products = []
        while S.recvlineS() == "+------------------------------------------+----------------------+------------------------------------------+\n":
            line = S.recvlineS().split("|")
            if len(line) != 5:
                break
            products.append(line[1].strip())
        logging.info(f"Done: {products[1:]}")
        return products[1:]

    def check_buy(self, S, product):
        logging.info(f"Buying product {product}...")
        self.check_menu(S)
        S.sendline(b"2")
        S.recvuntil(b"Product: ")
        S.sendline(product.encode())
        S.recvuntil(b"Here is the blueprint:\n")
        blueprint = S.recvlineS(keepends=False)
        logging.info(f"Done")
        return blueprint

    def check_edit(self, S, product):
        logging.info(f"Editing product {product}...")
        newcost = secrets.randbelow(1337)
        newblueprint = secrets.token_hex(secrets.randbelow(64)*128 + 128)

        self.check_menu(S)
        S.sendline(b"4")
        S.recvuntil(b"Product: ")
        S.sendline(product.encode())
        S.recvuntil(b"New Price: ")
        S.sendline(str(newcost).encode())
        S.recvuntil(b"Blueprint Length (hex): ")
        S.sendline(str(len(newblueprint)).encode())
        S.recvuntil(b"Blueprint Data (hex): ")
        S.sendline(newblueprint.encode())
        interface_assert("Records updated.\n", S.recvlineS())
        logging.info("Done")
        return newblueprint

    def check_bugmenu(self, S):
        response = S.recvuntil(b'> ')
        interface_assert(b"1. List Reports\n2. Show Report\n3. Edit Report\n4. Submit Report\n5. Return to main menu\n> ", response.lstrip())

    def check_bugs(self, S):
        logging.info("Checking bug menu...")
        report = secrets.token_hex(secrets.randbelow(4)*64 + 128)
        newreport = secrets.token_hex(len(report) // 2)

        self.check_menu(S)
        S.sendline(b"5")
        self.check_bugmenu(S)

        logging.info(f"Creating report {report}")
        S.sendline(b"3")
        interface_assert("No active bug report found. Creating new one...\n", S.recvlineS())
        S.recvuntilS(b"Size: ")
        S.sendline(str(len(report)).encode())
        S.recvuntilS(b"New Content: ")
        S.sendline(report.encode())

        self.check_bugmenu(S)
        S.sendline(b"2")
        S.recvuntilS(b"Current Report: ")
        interface_assert(report + "\n", S.recvlineS())

        logging.info(f"Changing report to {newreport}")
        S.sendline(b"3")
        S.recvuntilS(b"New Content: ")
        S.sendline(newreport.encode())

        self.check_bugmenu(S)
        S.sendline(b"2")
        S.recvuntilS(b"Current Report: ")
        interface_assert(newreport + "\n", S.recvlineS())

        self.check_bugmenu(S)
        S.sendline(b"4")

        self.check_bugmenu(S)
        S.sendline(b"5")
        logging.info("Done")

    def list_users(self, S):
        logging.info("Listing users...")
        self.check_menu(S)
        S.sendline(b"6")
        interface_assert("Here is what our dear users say about this service:\n", S.recvlineS())
        users = S.recvuntilS(b"\n\n").split("\n")[:-2]
        users = [":".join(user.split(":")[:-1]) for user in users]
        logging.info(f"Done: {users}")
        return users

    def check_service(self):
        logging.info('Check service')
        S = self.connection()
        S2 = None
        try:
            username, password = self.register(S, self.random_payment())
            product, data = self.check_create(S)
            products = self.check_list(S)
            if product not in products:
                logging.error(f"Product {product} not found")
                return checkerlib.CheckResult.FAULTY

            bought_data = self.check_buy(S, product)
            self.check_bugs(S)
            newdata = self.check_edit(S, product)
            S2 = self.connection()
            testuser, testpw = self.register(S2, self.random_payment())
            products = self.check_list(S)
            if product not in products:
                logging.error(f"Product {product} not found (after new connection)")
                return checkerlib.CheckResult.FAULTY
            newbought = self.check_buy(S2, product)
            users = self.list_users(S)

            if data != bought_data:
                logging.error(f"Bought data {bought_data} does not equal creation data {data}")
                return checkerlib.CheckResult.FAULTY
            if newdata != newbought:
                logging.error(f"Buying edited data {newbought} does not equal edit data {newdata}")
                return checkerlib.CheckResult.FAULTY
            if testuser not in users:
                logging.error(f"User {testuser} doesn't show up in user list")
                return checkerlib.CheckResult.FAULTY
        except InvalidInterface as e:
            logging.error(f"Failure while checking service: {e}")
            return checkerlib.CheckResult.FAULTY
        finally:
            S.close()
            S2 and S2.close()
        return checkerlib.CheckResult.OK

    def check_flag(self, tick):
        state = checkerlib.load_state(str(tick))
        if not state:
            logging.warning(f'No state information found for tick {tick}')
            return checkerlib.CheckResult.FLAG_NOT_FOUND
        username, password = state

        S = self.connection()
        try:
            flag = self.login(S, username, password)
            expected = checkerlib.get_flag(tick)
            if flag != expected:
                logging.error(f'Flag mismatch "{flag}" != "{expected}"')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
        except InvalidInterface as e:
            logging.error(f"Failure while checking flag: {e}")
            return checkerlib.CheckResult.FAULTY
        finally:
            S.close()

        return checkerlib.CheckResult.OK


if __name__ == '__main__':
    checkerlib.run_check(DbChecker)
