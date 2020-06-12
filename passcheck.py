import requests
from hashlib import sha1
import sys


def request_api_data(query_char):
    URL = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(URL)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching: {response.status_code}, check the api and try again")
    return response


def get_leaks_count(response, hash_to_check):
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if hash_to_check == h:
            return count
    return 0


def check_pwned_api(password):
    passw = sha1(password.encode()).hexdigest().upper()
    first_5_char, tail = passw[:5], passw[5:]
    response = request_api_data(first_5_char)
    return get_leaks_count(response, tail)


def main(args):
    for password in args:
        count = check_pwned_api(password)
        if count:
            print(f'{password} was found {count} times... You should probably change it!')
        else:
            print(f'{password} was NOT found! Carry on!!!')


if __name__ == '__main__':
    main(sys.argv[1:])
