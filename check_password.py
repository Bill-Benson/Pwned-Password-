import requests
import hashlib
import sys


def request_api_data_for(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    result = requests.get(url)
    if result.status_code != 200:
        raise RuntimeError(f"[-] Error fetching data \n {result.status_code}")
    return result


def get_password_leaks_count(hashes, hashes_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h.lower() == hashes_to_check.lower():
            return count
    return 0


def check_password_leaks(password):
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest()
    first5_char, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data_for(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = check_password_leaks(password)
        if count:
            print(f"{password} was found in {count} data breaches, you should probably change/upgrade it")
        else:
            print(f"{password} was not found in any known data breach, carry on with it")

    return "[+] Done!"


if __name__ == "__main__":
    main(sys.argv[1:])
