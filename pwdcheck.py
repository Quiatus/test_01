import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'http://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code} ')
    return res


def get_pwd_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return (count)
    return 0


def pwned_api_check(pwd):
    sha1pwd = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    first_5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_api_data(first_5_char)
    return get_pwd_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times!')
        else:
            print(f'{password} was not found!')
    return ('Completed!')


main(sys.argv[1:])