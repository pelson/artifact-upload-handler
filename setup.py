from codecs import open
from os import path
from setuptools import setup, find_packages


here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='conda-upload-server',
    version='1.0',
    description='A lightweight webservice capable of updating a local conda channel',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/SciTools-incubator/artifact-upload-handler',

    author='SciTools contributors',
    author_email='scitools-iris-dev@googlegroups.com',

    classifiers=[
        'Development Status :: 3 - Alpha',
    ],

    keywords='conda upload channel',
    packages=find_packages(),

    python_requires='>=3.5',
    install_requires=[
        'tornado'],

    entry_points={  # Optional
        'console_scripts': [
            'conda-upload-server=conda_upload_server.cli:main',
        ],
    },

    project_urls={
        'Source': 'https://github.com/SciTools-incubator/artifact-upload-handler',
    },
)
