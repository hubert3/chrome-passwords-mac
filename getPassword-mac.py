#!/usr/local/bin/python3

import sqlite3, os, binascii, subprocess, base64, sys, hashlib, argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

parser = argparse.ArgumentParser(description='Decrypt and update Chrome saved passwords for websites')
parser.add_argument('-f','--file', nargs='?', help='Chrome browser "Login Data" database file location (default ~/Library/Application Support/Google/Chrome/Default/Login Data)', default='%s/Library/Application Support/Google/Chrome/Default/Login Data' % os.path.expanduser("~"))
parser.add_argument('-b','--base', nargs='?', help='Base password to match')
parser.add_argument('-n','--new', nargs='?', help='New password to set for all entries matching base password')
args = parser.parse_args()

safeStorageKey = subprocess.check_output("security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'", shell=True).decode().replace("\n", "").replace("\"", "").encode()
if safeStorageKey == "":
    print("ERROR getting Chrome Safe Storage Key")
    sys.exit()

loginData = [args.file]

database = sqlite3.connect('file:%s' % loginData[0], uri=True)
iv = ''.join(('20',) * 16) #salt, iterations, iv, size - https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
key = hashlib.pbkdf2_hmac('sha1', safeStorageKey, b'saltysalt', 1003)[:16]

changePassOutput = 'Looking for passwords matching %s\n\n' % args.base
encryptedPasswordsToUpdate = set()
encryptedNewPass = ''

def chromeEncrypt(plaintext, iv, key=None):
    hexIv = binascii.unhexlify(iv)
    cipher = AES.new(key, AES.MODE_CBC, hexIv)
    paddedPlaintext = pad(plaintext.encode('utf-8'), 32)
    ciphertext = cipher.encrypt(paddedPlaintext)
    return(b'v10'+ciphertext)

def chromeDecrypt(encrypted_value, iv, key=None): #AES decryption using the PBKDF2 key and 16x ' ' IV, via openSSL (installed on OSX natively)
    hexIv = binascii.unhexlify(iv)
    hexEncPassword = base64.b64encode(encrypted_value[3:])
    cipher = AES.new(key, AES.MODE_CBC, hexIv)
    plaintext = unpad(cipher.decrypt(encrypted_value[3:]), 16).decode()
    #print ('Cipher: %s\nPlain:  %s\nRe-enc: %s\n' % (hexEncPassword, plaintext, chromeEncrypt(plaintext, iv, key)))
    return(plaintext)

def chromeProcess(safeStorageKey, profile):
    global changePassOutput, iv, key, database, encryptedPasswordsToUpdate

    sql = 'select username_value, password_value, origin_url from logins'
    decryptedList = []
    with database:
        for user, encryptedPass, url in database.execute(sql):
            if user == "" or (encryptedPass[:3] != b'v10'): #user will be empty if they have selected "never" store password
                continue

            else:
                decryptedPass = chromeDecrypt(encryptedPass, iv, key=key)
                if args.base and args.base.lower() in decryptedPass.lower():
                    changePassOutput += '\033[1m%s\033[0m \033[32mPass:\033[0m %s\n' % (url, decryptedPass)
                    encryptedPasswordsToUpdate.add(encryptedPass)
                urlUserPassDecrypted = (url, user, decryptedPass)
                decryptedList.append(urlUserPassDecrypted)
    return decryptedList

# main

output = "\n"
for profile in loginData:
    for i, x in enumerate(chromeProcess(safeStorageKey, "%s" % profile)):
        output += "%s[%s]%s %s%s%s\n\t%sUser%s: %s\n\t%sPass%s: %s\n" % ("\033[32m", (i + 1), "\033[0m", "\033[1m", x[0], "\033[0m", "\033[32m", "\033[0m", x[1], "\033[32m", "\033[0m", x[2])

print(output)

if args.base:
    print(changePassOutput)

    if args.new:
        if not input("Changing above saved passwords to %s\n\nAre you sure? (y/n): " % args.new).lower().strip()[:1] == "y":
            sys.exit(1)
        encryptedNewPass = chromeEncrypt(args.new, iv, key)
        with database:
            for pwd in encryptedPasswordsToUpdate:
                database.execute('update logins set password_value = ? where password_value = ?', (encryptedNewPass, pwd))
