# chrome-passwords-mac
Forked from https://github.com/mooredh/chrome-passwords-mac

This python script decrypts and prints the website passwords saved by Chrome on Mac

If given -b and -n parameters, it also updates all passwords matching a certain base password with a new password in the Chrome DB

Quit Chrome before running the script. You will be asked to authenticate with your Mac login once for keychain access.

Working as of 2021-03-19 with: 

Mac OS Big Sur 11.2.3
Chrome 89.0.4389.90 (Official Build) (x86_64)
Python 3.9.2 (installed from homebrew)

Run 

`% ./getPassword-mac.py | less -R`

To page through output with colours

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
