"""
A tornado application to handle uploading a conda build artifact to a specified
file location.

"""

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

import tornado.httpserver
import tornado.ioloop
from tornado.log import enable_pretty_logging
import tornado.web
from tornado.web import RequestHandler, Finish

from .token import DEFAULT_SALT, check_token as _check_token


logger = logging.getLogger(__name__)


__version__ = '0.1.0dev0'


class ArtifactUploadHandler(RequestHandler):
    """Handle writing conda build artifacts to a channel."""

    def initialize(self, write_path, conda_exe, hash_expected):
        """
        "Hook for subclass initialization."

        In this class, when we initialize `ArtifactUploadHandler`, we need to
        set:
         * the path that incoming files will be written to, which may be
           appended with the sub-directory arch, if provided by the client,
         * the path to the conda executable to use for indexing the channel,
         * the expected hashed and salted digest of the secure upload token.

        """
        self.write_path = write_path
        self.conda_exe = conda_exe
        self.hash_expected = hash_expected

    def _conda_index(self, directory):
        """
        Update the package index metadata files in the provided directory.

        """
        cmds = [self.conda_exe, 'index', directory]
        output = subprocess.check_output(cmds)
        logger.info('\n' + output.decode('utf-8').strip())

    def post(self):
        token = self.get_argument('token', default=None)
        file_data, = self.request.files['artifact']
        filename = file_data['filename']
        body = file_data['body']

        if not _check_token(self.hash_expected, DEFAULT_SALT, token):
            self.set_status(401)
            logger.info('Unauthorized token request')
            raise Finish()

        f = io.BytesIO(body)
        subdir = subdir_of_binary(f)

        directory = os.path.join(self.write_path, subdir)
        if not os.path.exists(directory):
            logger.info('Creating a new channel at {}'.format(directory))
            os.makedirs(directory)
        target = os.path.join(directory, filename)

        # Don't overwrite existing binaries.
        if os.path.exists(target):
            self.set_status(401)
            logger.info('Attempting to overwrite an existing binary')
            raise Finish()

        with open(target, 'wb') as owfh:
            owfh.write(body)
        self._conda_index(directory)


def subdir_of_binary(fh):
    """Given a file handle to a tar.bz2 conda binary, identify the arch"""
    subdir = None
    with tarfile.open(fileobj=fh, mode="r:bz2") as tar:
        fh = tar.extractfile('info/index.json')
        if fh is not None:
            index = json.loads(fh.read().decode('utf-8'))
            subdir = index.get('subdir', None)
    if not subdir:
        raise ValueError('Subdir cannot be determined for binary')
    return subdir


def make_app(write_path, conda_exe, token_hash):
    kw = {'write_path': write_path,
          'conda_exe': conda_exe,
          'hash_expected': token_hash}
    return tornado.web.Application([(r'/', ArtifactUploadHandler, kw)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--write_dir",
                        help="directory to write artifacts to",
                        default=os.getcwd(),
                        )
    parser.add_argument("-p", "--port",
                        help="webserver port number",
                        default=8080,
                        )
    parser.add_argument("-e", "--conda_exe",
                        help="full path to conda executable",
                        default=None,
                        )
    parser.add_argument("-c", "--certfile",
                        help="full path to certificate file for SSL",
                        default=None,
                        )
    parser.add_argument("-k", "--keyfile",
                        help="full path to keyfile for SSL",
                        default=None,
                        )
    parser.add_argument("-t", "--token_hash",
                        help="hash of secure token",
                        default=None,
                        )

    args = parser.parse_args()
    write_path = args.write_dir
    port = args.port
    conda_exe = args.conda_exe
    certfile = args.certfile
    keyfile = args.keyfile
    token_hash = args.token_hash


    if not conda_exe:
        conda_exe = distutils.spawn.find_executable("conda")

    if certfile or keyfile:
        ssl_opts = {'certfile': certfile,
                    'keyfile': keyfile}
    else:
        ssl_opts = None

    enable_pretty_logging()

    url = '{protocol}{host}:{port}'.format(
        protocol='https://' if ssl_opts else 'http://',
        host='localhost',
        port=port)

    logger.info('Serving on {url}'.format(url=url))

    app = make_app(write_path, conda_exe, token_hash)
    server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_opts)
    server.listen(port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
