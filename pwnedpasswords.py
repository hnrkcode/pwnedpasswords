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


async def _fetch_hashes(session, url):
    async with session.get(url) as response:
        return await response.text()


async def check_password(work_queue):
    async with aiohttp.ClientSession() as session:
        while not work_queue.empty():
            password = await work_queue.get()
            password_hash = _hashify(password)
            prefix, suffix = password_hash[:5], password_hash[5:]
            url = f"{API_URL}{prefix}"
            fetched_hashes = await _fetch_hashes(session, url)
            password_leak_count = _get_matching_hash_count(suffix, fetched_hashes)
            print(f"LEAKS FOUND: {password_leak_count}, {password}")


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

    limit = 10
    tasks = [asyncio.create_task(check_password(work_queue)) for _ in range(limit)]

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
