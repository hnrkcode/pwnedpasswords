import argparse
import csv
import hashlib
import sys
from collections import defaultdict

import requests


API_URL = "https://api.pwnedpasswords.com/range/"


def _hashify(password):
    """Returns an uppercase hash value of the password."""
    hash = hashlib.sha1()
    hash.update(bytes(password, encoding="utf-8"))

    return hash.hexdigest().upper()


def _get_matching_hash_count(suffix, data):
    """Locally count the hashes that matches the passwords hash."""
    password_leak_count = 0
    lines = data.text.split("\n")

    for line in lines:
        if line[:35] == suffix:
            password_leak_count = int(line[36:])

    return password_leak_count


def _message(password, password_leak_count):
    """Print the result to the screen."""
    if password_leak_count:
        numerus = lambda num: "time." if num == 1 else "times!"
        print(f'"{password}" have been pwned {password_leak_count} {numerus(password_leak_count)}')
    else:
        print(f'No match for "{password}".')


def check_password(password, msg=False):
    """Hash password and check it against hashes of leaked passwords."""
    password_hash = _hashify(password)
    prefix, suffix = password_hash[:5], password_hash[5:]

    try:
        fetched_hashes = requests.get(f"{API_URL}{prefix}")
    except requests.exceptions.ConnectionError:
        sys.exit("Connection error.")

    password_leak_count = _get_matching_hash_count(suffix, fetched_hashes)

    if msg:
        _message(password, password_leak_count)

    return password_leak_count


def check_csv(file):
    column = defaultdict(list)
    try:
        with open(file) as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                for key, value in row.items():
                    column[key].append(value)
    except FileNotFoundError as e:
        sys.exit(e)

    for login_details in zip(column["username"], column["password"]):
        username = login_details[0]
        password = login_details[1]
        password_leak_count = check_password(password)

        if password_leak_count:
            numerus = lambda num: "time." if num == 1 else "times!"
            print(
                f'Password "{password}" for "{username}"',
                f"appeared {password_leak_count} {numerus(password_leak_count)}",
            )


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", help="Check single password.")
    group.add_argument("-f", "--csvfile", help="Check passwords in CSV-file.")
    args = parser.parse_args()

    if args.password:
        check_password(args.password, msg=True)

    if args.csvfile:
        check_csv(args.csvfile)


if __name__ == "__main__":
    main()
