#!/usr/bin/env python3.6

import os
import sys
import hashlib
import requests
import argparse


class CheckPassword:

    def __init__(self):
        self.url = "https://api.pwnedpasswords.com/range/"
        self.temp = "hashes.txt"

    def _hashify(self, password):
        """Returns an uppercase hash value of the password."""
        hash = hashlib.sha1()
        hash.update(bytes(password, encoding="utf-8"))
        return hash.hexdigest().upper()

    def _save_temp(self, hashes):
        """Temporary store the fetched hashes in a file."""
        with open(self.temp, "w") as output:
            output.write(hashes)

    def _remove_temp(self):
        """Delete the temporary file with fetched hashes."""
        os.remove(self.temp)

    def _count(self, suffix):
        """Locally count the hashes that matches the passwords hash."""
        occur = 0
        with open(self.temp) as f:
            for line in f.readlines():
                if line[:35] == suffix:
                    occur = int(line[36:])
        self._remove_temp()
        return occur

    def check(self, password):
        """Hash password and check it against hashes of leaked passwords."""
        password_hash = self._hashify(password)
        prefix, suffix = password_hash[:5], password_hash[5:]
        try:
            fetched_hashes = requests.get(f"{self.url}{prefix}")
        except requests.exceptions.ConnectionError as e:
            sys.exit("Connection error.")
        else:
            # Temporary store the fetched hashes in a file.
            self._save_temp(fetched_hashes.text)
            # Locally count the hashes that matches the passwords hash.
            occur = self._count(suffix)
            return occur


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("password", help="Password to hash and check.")
    args = parser.parse_args()
    haveibeenpwned = CheckPassword()
    occur = haveibeenpwned.check(args.password)

    if occur > 0:
        numerus = lambda num: "time." if num == 1 else "times!"
        print(f"\"{args.password}\" have been pwned {occur} {numerus(occur)}")
    elif occur == 0:
        print(f"\"{args.password}\" doesn't appear to be pwned.")


if __name__ == "__main__":
    main()
