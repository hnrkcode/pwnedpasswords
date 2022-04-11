import argparse
import asyncio
import csv
import hashlib
import sys
from collections import defaultdict
from typing import Any, Generator

import aiohttp

API_URL = "https://api.pwnedpasswords.com/range/"


def _hashify(password: str) -> str:
    """Returns an uppercase hash value of the password."""
    hash = hashlib.sha1()
    hash.update(bytes(password, encoding="utf-8"))
    password_hash = hash.hexdigest().upper()

    return password_hash


def _get_matching_hash_count(suffix: str, data: str) -> int:
    """Get how many hashes that matched the passwords hash."""
    password_leak_count = 0

    for line in data.split("\n"):
        if line[:35] == suffix:
            password_leak_count = int(line[36:])

    return password_leak_count


def _password_batch(passwords: list, size: int) -> Generator:
    for i in range(0, len(passwords), size):
        yield passwords[i : i + size]


async def _fetch_hashes(session: Any, url: str) -> Any:
    async with session.get(url) as response:
        return await response.text()


async def check_password(work_queue: asyncio.queues.Queue) -> None:
    async with aiohttp.ClientSession() as session:
        while not work_queue.empty():
            password = await work_queue.get()
            password_hash = _hashify(password)
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            url = f"{API_URL}{prefix}"
            fetched_hashes = await _fetch_hashes(session, url)
            password_leak_count = _get_matching_hash_count(suffix, fetched_hashes)

            print(f"LEAKS FOUND: {password_leak_count}, {password}")


async def main() -> None:
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

    batch_size = 50
    batches = _password_batch(passwords, batch_size)

    # Split up passwords into smaller batches to avoid rate limits.
    for batch in batches:
        work_queue: asyncio.queues.Queue = asyncio.Queue()

        for password in batch:
            await work_queue.put(password)

        limit = 10
        tasks = [asyncio.create_task(check_password(work_queue)) for _ in range(limit)]

        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
