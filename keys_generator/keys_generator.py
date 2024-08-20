#  © 2024 AxonOps Limited. All rights reserved.

#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at

#      http://www.apache.org/licenses/LICENSE-2.0

#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Cassandra Workbench tool to generate RSA keys,
# that will be used to encrypt/decrypt credentials securely with cqlsh tool

from platform import system
from keyring import get_password, set_password, set_keyring, backends
from Crypto.PublicKey import RSA
from os import getenv

if system() == 'Windows':
    try:
        from keyring.backends.Windows import WinVaultKeyring

        set_keyring(WinVaultKeyring())
    except:
        pass

if system() == 'Linux':
    try:
        get_password("AxonOpsWorkbenchPublicKey", "key")
    except:
        try:
            from keyring.backends import libsecret

            set_keyring(libsecret.Keyring())
        except:
            pass

try:
    # First, attempt get the keys from the OS keychain
    publicKey, privateKey = get_password("AxonOpsWorkbenchPublicKey", "key"), \
                            get_password("AxonOpsWorkbenchPrivateKey", "key")


    def generateKeys(length):
        global publicKey, privateKey

        # Check that they're saved in the OS keychain and valid if so
        # If not, then create both keys
        if publicKey is None or privateKey is None:
            keys = RSA.generate(length)  # Setting the length to 4096 caused a failure on Windows (issue #105)

            # Get public and private keys,
            # encode them with base64, and convert them from bytes to string
            publicKey, privateKey = keys.publickey().exportKey(), keys.exportKey()
            publicKey, privateKey = publicKey.decode("utf-8"), privateKey.decode("utf-8")

            # Now set both keys in the OS keychain
            set_password(
                "AxonOpsWorkbenchPublicKey",
                "key", publicKey)
            set_password(
                "AxonOpsWorkbenchPrivateKey",
                "key", privateKey)


    try:
        if system() == 'Windows':
            raise Exception()
        
        generateKeys(int(getenv("RSA_KEY_LENGTH", 2048)))
    except:
        try:
            generateKeys(int(getenv("RSA_KEY_LENGTH", 1024)))
        except:
            pass
        pass

    # Print the public key
    print(publicKey)
except:
    pass