import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "S20Control",
    version = "0.1",
    author = "Glen Pitt-Pladdy / Guy Sheffer",
    author_email = "glenpp@users.noreply.github.com",
    description = ("Python management utility for Orvibo S20 WiFi Plug"),
    license = "GNU",
    keywords = "s20 orvibo orvibos20",
    url = "https://github.com/glenpp/OrviboS20",
    packages=['S20control'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Beta",
        "Topic :: Utilities",
        "License :: GNU License",
    ],
    entry_points = {
        'console_scripts': [
            'S20control = S20control.S20control:main',                  
            ],              
        },
)
