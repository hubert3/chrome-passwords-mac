chrome-passwords-mac
====================

Forked from https://github.com/mooredh/chrome-passwords-mac

This python script decrypts and prints the website passwords saved by Chrome on Mac.

It can also update all passwords matching a certain base password to a new password in the Chrome password DB.

Working as of 2022-12-25 with: 

* Mac OS Ventura 13.1
* Chrome 108.0.5359.124 (Official Build) (arm64 or x86_64)
* Python 3.9.6 (Ventura default)

Instructions
------------

`pip3 install pycryptodome` (3.16.0 works)

(Should be installed into /usr/local/lib/python3.9/site-packages/Crypto if using Python 3.9 from Homebrew. If you have an existing lowercase 'crypto' folder here from an older Python crypto module you need to delete this first)

Quit Chrome before running the script. 

You will be asked to authenticate with your Mac login once for keychain access.

Run:

`% ./getPassword-mac.py | less -R`

To dump your Chrome passwords and page through the output with colours.

Use `-b <base password>` to show URLs and passwords which contain this base password

Use `-b <base password>` together with `-n <new password>` to update all matching passwords to the specified new password.

```% ./getPassword-mac.py -h
usage: getPassword-mac.py [-h] [-f [FILE]] [-b [BASE]] [-n [NEW]]

Decrypt and update Chrome saved passwords for websites

optional arguments:
  -h, --help            show this help message and exit
  -f [FILE], --file [FILE]
                        Chrome browser "Login Data" database file location (default ~/Library/Application Support/Google/Chrome/Default/Login Data)
  -b [BASE], --base [BASE]
                        Base password to match
  -n [NEW], --new [NEW]
                        New password to set for all entries matching base password


```
