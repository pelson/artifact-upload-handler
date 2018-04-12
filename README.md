# artifact-upload-handler

A secure webserver to handle uploading CI conda build artifacts to a specified conda channel.

To use, simply clone this repo and run the Python webserver, observing the
[Usage](#usage) and [Requirements](#requirements) instructions below.


## Usage

```
usage: artifact_upload_handler.py [-h] -d WRITE_DIR -p PORT -e CONDA_EXE -c
                                  CERTFILE -k KEYFILE -t TOKEN_HASH

optional arguments:
  -h, --help            show this help message and exit
  -d WRITE_DIR, --write_dir WRITE_DIR
                        directory to write artifacts to
  -p PORT, --port PORT  webserver port number
  -e CONDA_EXE, --conda_exe CONDA_EXE
                        full path to conda executable
  -c CERTFILE, --certfile CERTFILE
                        full path to certificate file for SSL
  -k KEYFILE, --keyfile KEYFILE
                        full path to keyfile for SSL
  -t TOKEN_HASH, --token_hash TOKEN_HASH
                        hash of secure token
```


### Usage Example 

For example, to start a secure webserver running on port 9999 that will write
linux-64 packages to the (imaginary) conda channel at ``/path/to/conda/channel``:

```
$ python artifact_upload_handler.py -d /path/to/conda/channel/linux-64 \
                                    -p 9999 \
                                    -e /path/to/env/bin/conda \
                                    -c /path/to/mycertfile.crt \
                                    -k /path/to/mykeyfile.key \
                                    -t eccd989b

```

To test the webserver:

```python
import requests

artifacts = [open('my-artifact1-1.0.0-2.tar.bz2', 'rb'),
             open('my-artifact2-3.4.2-0.tar.bz2', 'rb'),
             open('my-artifact3-0.9.1-0.tar.bz2', 'rb'),
            ]
url = 'https://localhost:9999/'
token = 'mysecuretoken'

for artifact in artifacts:
    requests.post(url, data={'token': token}, files={'artifact': artifact},
                  verify=False)

```

The webserver handles one artifact per ``POST`` request, which is replicated
here by the loop over the sample artifacts.
The dictionary key names ``'token'`` and ``'artifact'`` in the request must be
observed. These keys are expected by the webserver when handling the request.

Note that in order to prevent unauthorised uploads to the channel, the request 
must be accompanied by a secure token that, when salted and hashed, matches the
salted and hashed token specified when the webserver is set up
(see [Usage](#usage) above). An expected use-case of this server is to handle
build artifacts produced from CI. In such a use-case, this secure token would be
defined in the CI pipeline and is passed in unhashed form. We rely on the secured
nature of the server to prevent the unhashed token being revealed.


### Requirements

Requires [tornado](http://www.tornadoweb.org/en/stable/index.html) and ``hmac`` v2.7.7+.
