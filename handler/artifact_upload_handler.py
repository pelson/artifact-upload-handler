"""
A tornado application to handle uploading a conda build artifact to a specified
file location.

"""

import argparse
import hashlib
import hmac
import os
import subprocess

import tornado.ioloop
import tornado.httpserver
import tornado.web


class ArtifactUploadHandler(tornado.web.RequestHandler):
    """Handle writing conda build artifacts to a channel."""

    def initialize(self, write_path, conda_exe, hash_expected):
        """
        "Hook for subclass initialization."

        In this class, when we initialize `ArtifactUploadHandler`, we need to
        set:
         * the path that incoming files will be written to,
         * the path to the conda executable to use for indexing the channel,
         * the expected hashed and salted digest of the secure upload token.

        """
        self.write_path = write_path
        self.conda_exe = conda_exe
        self.hash_expected = hash_expected

    def _check_token(self, token):
        """
        Check we have been passed the *correct* secure token before uploading
        the artifact to the channel.
        
        """
        salt = '42679ad04d44c96ed27470c02bfb28c3'
        to_hash = '{}{}'.format(salt, token)
        hash_result = hashlib.sha256(to_hash).hexdigest()
        # Reduce the risk of timing analysis attacks.
        return hmac.compare_digest(self.hash_expected, hash_result)

    def _index_channel(self):
        """
        Index the conda channel at `self.write_path` to ensure the channel
        remains consistent.
        
        """
        cmds = [self.conda_exe, 'index', self.write_path]
        subprocess.check_call(cmds)

    def post(self):
        token = self.get_argument('token')
        file_data, = self.request.files['artifact']
        filename = file_data['filename']
        body = file_data['body']
        if self._check_token(token):
            with open(os.path.join(self.write_path, filename), 'w') as owfh:
                owfh.write(body)
            self._index_channel()


def make_app(write_path, conda_exe):
    kw = {'write_path' :write_path,
          'conda_exe': conda_exe,
          'token_hash': token_hash}
    return tornado.web.Application([(r'/', ArtifactUploadHandler, kw)])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--write_dir",
                        help="directory to write artifacts to",
                        required=True,
                       )
    parser.add_argument("-p", "--port",
                        help="webserver port number",
                        required=True,
                       )
    parser.add_argument("-e", "--conda_exe",
                        help="full path to conda executable",
                        required=True,
                       )
    parser.add_argument("-c", "--certfile",
                        help="full path to certificate file for SSL",
                        required=True,
                       )
    parser.add_argument("-k", "--keyfile",
                        help="full path to keyfile for SSL",
                        required=True,
                       )
    parser.add_argument("-t", "--token_hash",
                        help="secure token hash",
                        required=True,
                       )
    args = parser.parse_args()
    write_path = args.write_dir
    port = args.port
    conda_exe = args.conda_exe
    certfile = args.certfile
    keyfile = args.keyfile
    token_hash = args.token_hash

    ssl_opts = {'certfile': certfile,
                'keyfile': keyfile}
    app = make_app(write_path, conda_exe, token_hash)
    https_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_opts)
    https_server.listen(port)
    tornado.ioloop.IOLoop.current().start()

