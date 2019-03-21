#!/usr/bin/env python3.6

import os
import sys
import hashlib
import requests
import argparse


def hashify(password):
    """Hash function that returns a uppercase hash value of the password."""
    hash = hashlib.sha1()
    hash.update(bytes(password, encoding="utf-8"))
    hash = hash.hexdigest().upper()
    return hash


def check_password(hash):
    """Get all hashes in the database that matches the five first characters
    in the passwords hash value.
    Then check how many times the password occurred in the databases."""
    # Get hashes that match the five first characters and save them to a file.
    prefix, suffix = hash[:5], hash[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    except requests.exceptions.ConnectionError as e:
        sys.exit("Connection error.")
    else:
        with open("hashes.txt", "w") as output:
            output.write(r.text)
        # Locally count how many of the hashes that matches the passwords hash.
        with open("hashes.txt") as f:
            for line in f.readlines():
                if line[:35] == suffix:
                    occurrence = int(line[36:])
                    os.remove("hashes.txt")
                    return occurrence
            os.remove("hashes.txt")
            return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("password", help=("Password that will be hashed and" +
                        " checked locally against hashes of leaked" +
                        " passwords on haveibeenpwned.com")
                        )
    args = parser.parse_args()
    hash = hashify(args.password)
    occurrence = check_password(hash)

    if occurrence == 1:
        print(f"Your password occurred {occurrence} time in the database.")
        print("You should change your password.")
    elif occurrence > 1:
        print(f"Your password occurred {occurrence} times in the database.")
        print("You should change your password.")
    elif occurrence == 0:
        print(f"Your password was not in the database.")


if __name__ == "__main__":
    main()
