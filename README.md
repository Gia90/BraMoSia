# BraMoSia
Brand Model Automatic Identification Script

**BraMoSia** is a command line tool that gathers as much info as possible about brand, model, firmware version and anything else of a target AP device (for default passwords identification or possible known model specific vulnerabilities).

The more arguments the user specifies, the more methods it will try to obtain info and so more info it will be able to extract.

# Setup

## Requirements
+ Python 2.7
+ pip
+ virtualenv

## Instructions
1. Clone the project
1. Create python virtual environment with `virtualenv --python=/usr/bin/python2.7 .env`
1. Activate the virtual env with `source .env/bin/activate`
1. Install all the required python dependencies with `pip install -r requirements.txt`
1. Run BraMoSia with `python bramosia`

# Usage

Currently accepted args:
* Mac-Address (OUI lookup)
* IP if the device is reachable (upnp, snmp, other?)
* BSSID (beacon, probe requests)

Run `bramosia --help` command to get complete usage info.
