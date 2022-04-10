import argparse
import asyncio
import csv
import hashlib
import sys
from collections import defaultdict

import aiohttp

API_URL = "https://api.pwnedpasswords.com/range/"


def _hashify(password):
    """Returns an uppercase hash value of the password."""
    hash = hashlib.sha1()
    hash.update(bytes(password, encoding="utf-8"))

    return hash.hexdigest().upper()


def _get_matching_hash_count(suffix, data):
    """Locally count the hashes that matches the passwords hash."""
    password_leak_count = 0
    lines = data.split("\n")

    for line in lines:
        if line[:35] == suffix:
            password_leak_count = int(line[36:])

    return password_leak_count


def _message(password, password_leak_count):
    """Print the result to the screen."""
    if password_leak_count:
        numerus = lambda num: "time." if num == 1 else "times!"
        print(
            f'"{password}" have been pwned {password_leak_count} {numerus(password_leak_count)}'
        )
    else:
        print(f'No match for "{password}".')


async def check_password(work_queue):
    async with aiohttp.ClientSession() as session:
        while not work_queue.empty():
            password = await work_queue.get()

            password_hash = _hashify(password)
            prefix, suffix = password_hash[:5], password_hash[5:]

            async with session.get(f"{API_URL}{prefix}") as response:
                fetched_hashes = await response.text()
                password_leak_count = _get_matching_hash_count(suffix, fetched_hashes)
                _message(password, password_leak_count)


async def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", help="Check single password.")
    group.add_argument("-f", "--csvfile", help="Check passwords in CSV-file.")
    args = parser.parse_args()

    passwords = []

    if args.password:
        passwords.append(args.password)

    if args.csvfile:
        column = defaultdict(list)

        try:
            with open(args.csvfile) as csvfile:
                csvreader = csv.DictReader(csvfile)
                for row in csvreader:
                    for key, value in row.items():
                        column[key].append(value)
        except FileNotFoundError as e:
            sys.exit(e)

        for password in column["password"]:
            passwords.append(password)

    work_queue = asyncio.Queue()

    for password in passwords:
        await work_queue.put(password)

    await asyncio.gather(
        *[asyncio.create_task(check_password(work_queue)) for i in range(10)],
    )


if __name__ == "__main__":
    asyncio.run(main())
