import argparse
import distutils.spawn
import hashlib
import hmac
import io
import json
import logging
import os
import subprocess
import tarfile


#: A default salt is provided, but it is recommended to use your own.
DEFAULT_SALT = '42679ad04d44c96ed27470c02bfb28c3'


def generate_hash(token, *, salt=DEFAULT_SALT):
    to_hash = '{}{}'.format(salt, token)
    return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()


def check_token(hash_expected, salt, token):
    """Check we have been passed the correct secure token."""
    if hash_expected:
        hash_result = generate_hash(salt=salt, token=token)
        # Reduce the risk of timing analysis attacks.
        result = hmac.compare_digest(hash_expected, hash_result)
    else:
        assert token is None
        result = True
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--salt",
                        help="The (semi-)secret salt being used by the server",
                        default=DEFAULT_SALT,
                        )
    parser.add_argument("token",
                        help="The secret token/password made available to the client in plain-text",
                        )

    args = parser.parse_args()
    
    server_token = generate_hash(salt=args.salt, token=args.token)

    print('Server salt:  "{}"'.format(args.salt))
    print('Client token: "{}"'.format(args.token))
    print('Server token: "{}"'.format(server_token))

    assert check_token(server_token, args.salt, args.token)

    

if __name__ == '__main__':
    main()
