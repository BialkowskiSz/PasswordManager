#!/usr/bin/env python2.7

from __future__ import print_function
from base64 import b64encode, b64decode
import os.path
from sys import exit
from random import SystemRandom

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

from json import loads, dumps

from getpass import getpass

import pyperclip



"""
    Simple implementation of an encrypted password store.
    Author: Szymon Bialkowski
    Date:   15/01/2018

"""





#    Read in all user information
def readAllPasswords():
    userMessage     = "Enter in emails, passwords and notes. Type 'exit' on service if you're done."
    serviceName     = ""
    userEmail       = ""
    userPassword    = ""
    userNotes       = ""
    credentials     = {}

    print(userMessage)
    while True:
        serviceName     = raw_input("\nService:\t")

        if serviceName == 'exit':
            break

        userEmail       = raw_input("Email:\t\t")
        userPassword    = generatePassword(int(raw_input("Pass Length:\t")))
        userNotes       = raw_input("Notes:\t\t")

        credentials[serviceName] = {"email":    userEmail,
                                    "password": userPassword,
                                    "notes": userNotes
                                }
    return credentials


#   Simple function which returns input for overwriting vault
#   For readability purposes
def overwriteVaultQuestion():
    message = "Vault already exists. "
    message += "Are you sure you want to overwrite it? (y/n)\n"
    return raw_input(message)


#   Read password from user
def readAndReturnPassword():
    while True:
        password = raw_input("\nPlease enter in a strong master password.\n")
        if not 0 < len(password) < 256:
            print("Password length has to be between 0-256")
        else:
            return password

#    Generates random password using urandom
def generatePassword(length=30):
    characterSet    = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    randomGenerator = SystemRandom()
    password        = [  randomGenerator.choice(characterSet) for i in range(length)  ]
    return ''.join(password)



#   Create new vault
def createVault():
    print("\nCreating new vault...")
    if os.path.isfile("PasswordVault"):
        check = overwriteVaultQuestion()
        if check == 'y':
            password = readAndReturnPassword()
            print("\nCreating vault...")
            credentials = readAllPasswords()

            with open("PasswordVault", "w") as vault:
                #   All necessary arguments
                salt        = get_random_bytes(32)
                N           = 262144
                r           = 8
                p           = 1
                keyLenght   = 32
                nonce       = get_random_bytes(32)

                #   Perform scrypt key stretching
                password = scrypt(password, salt, keyLenght, N, r, p)

                aes = AES.new(password, AES.MODE_GCM, nonce=nonce)
                credentials = dumps(credentials)
                credentials, tag = aes.encrypt_and_digest(credentials)
                [vault.write(x) for x in (salt, aes.nonce, tag, credentials)]
                print("Vault successfully created.")



def openVault():
    vaultMessage = """\nVault Menu.
1: View.
2: Add.
3: Update.
4: Delete.
5: Encrypt and close vault.
6: Discard changes and close vault."""

    password = getpass("Please enter in your vault password: ")
    with open("PasswordVault", "r+") as vault:
        try:
            keyLenght   = 32
            salt, nonce, tag, ciphertext = [ vault.read(x) for x in (32, 32, 16, -1) ]
            password = scrypt(password, salt, keyLenght, 262144, 8, 1)
            aes = AES.new(password, AES.MODE_GCM, nonce=nonce)
            credentials = aes.decrypt_and_verify(ciphertext, tag)
            credentials = loads(credentials)

        except ValueError:
            print("Invalid password or vault has been tampered with.")
            raw_input()
            return None


    while True:
        try:
            print(vaultMessage)
            userInput = int(raw_input("Choice: "))

            if userInput == 1:
                viewVault(credentials)

            elif userInput == 2:
                serviceName     = raw_input("\nService:\t")
                userEmail       = raw_input("Email:\t\t")
                userPassword    = generatePassword(int(raw_input("Pass Length:\t")))
                userNotes       = raw_input("Notes:\t\t")

                credentials[serviceName] = {"email":    userEmail,
                                            "password": userPassword,
                                            "notes": userNotes
                                        }

            elif userInput == 3:
                updateVault(credentials)

            elif userInput == 4:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    if raw_input("Are you sure you want to delete {}? (y/n)\n".format(service)) == 'y':
                        del credentials[service]
                        print("Service deleted successfully.")
                        raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 5:
                with open("PasswordVault", "w") as vault:
                    nonce       = get_random_bytes(32)

                    aes = AES.new(password, AES.MODE_GCM, nonce=nonce)
                    credentials = dumps(credentials)
                    credentials, tag = aes.encrypt_and_digest(credentials)
                    [vault.write(x) for x in (salt, aes.nonce, tag, credentials)]
                    print("Vault successfully saved.")
                    raw_input()
                    break

            elif userInput == 6:
                break


        except Exception as e:
            print("Invalid input. Please try again.")


def viewVault(credentials):
    viewMessage = """\nView Menu.
1: Copy service password into clipboard.
2: Copy service email into clipboard.
3: Print service password. (CLEARTEXT!)
4: Print service email and notes.
5: Print all services.
6: Back to vault menu."""
    userInput = 0

    while True:
        print(viewMessage)


        try:
            userInput = int(raw_input("Choice: "))

            if userInput == 1:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    pyperclip.copy(credentials[service]['password'])
                    print("Password successfully copied to clipboard.")
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 2:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    pyperclip.copy(credentials[service]['email'])
                    print("Email successfully copied to clipboard.")
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 3:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    print(credentials[service]['password'])
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 4:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    print("Email: {}\nNotes: {}".format(credentials[service]['email'], credentials[service]['notes']))
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 5:
                print("\n{}".format('\n'.join(credentials)))
                raw_input()

            elif userInput == 6:
                break


        except ValueError:
            print("Please enter a valid number.")


def updateVault(credentials):
    updateMessage = """\nUpdate Menu.
1: Update service Email.
2: Generate new service Password.
3: Update service notes.
4: Concatenate to service notes.
5: Return to vault menu."""

    userInput = 0

    while True:
        print(updateMessage)


        try:
            userInput = int(raw_input("Choice: "))

            if userInput == 1:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    credentials[service]['email'] = raw_input("\nPlease enter new email.")
                    print("Email changed successfully.")
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 2:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    credentials[service]['password'] = generatePassword(int(raw_input("\nPassword length: ")))
                    print("Password changed successfully.")
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 3:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    credentials[service]['notes'] = raw_input("\nNew {} service notes: ".format(service))
                    print("Notes changed successfully.")
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 4:
                try:
                    service = raw_input("\nPlease enter service name: ")
                    credentials[service]['notes'] += raw_input("\nConcatenate to {} service notes: ".format(service))
                    print("Notes concatenated successfully.")
                    raw_input()
                except KeyError:
                    print("\"{}\" service does not exist.".format(service))
                    raw_input()

            elif userInput == 5:
                break

        except ValueError:
            print("Please enter a valid number.")


def main():
    welcomeMessage = """\nPassword Manager.
Please choose one of the following options.
1: Create new vault.
2: Open existing vault.
3: Exit.
    """
    userInput = 0

    print(welcomeMessage)

    while True:
        try:
            userInput = int(raw_input("Choice: "))
            if userInput == 1:
                createVault()
                print(welcomeMessage)
            elif userInput == 2:
                openVault()
                print(welcomeMessage)
            elif userInput == 3:
                print("Thank you for using my Password Manager.")
                exit()
            else:
                print(welcomeMessage)
                print("\nInvalid option. Please try again.")
        except ValueError as e:
            print(welcomeMessage)
            print("\nPlease enter a number.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nThank you for using my Password Manager.")
        try:
            exit(0)
        except SystemExit:
            os._exit(0)
