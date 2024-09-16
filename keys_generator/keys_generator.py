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

# AxonOps Workbench Keys Generator Tool
# This tool is used for generating RSA public/private keys; which is then used for the encryption/decryption processes for a more secure and reliable credentials-storing approach

from platform import system
from keyring import get_password, set_password, set_keyring, backends
from Crypto.PublicKey import RSA
from os import getenv

# Define the names of the public and private keys
public_key_name, private_key_name = "AxonOpsWorkbenchPublicKey", \
                                    "AxonOpsWorkbenchPrivateKey"

try:
    get_password(public_key_name, "key")
except:
    try:
        # In case the tool is running on Windows it'll switch to a supported keyring backend `WinVault`
        if system() == "Windows":
            set_keyring(backends.Windows.WinVaultKeyring())

        # When running on Linux - regardless the distribution - it'll switch to a supported keyring backend `LibSecret`
        if system() == "Linux":
            set_keyring(backends.libsecret.Keyring())
    except:
        pass

try:
    # Attempt to get the keys from the OS keychain
    public_key, private_key = get_password(public_key_name, "key"), \
                            get_password(private_key_name, "key")

    # Function to generate the RSA keys based on a given `length`
    def generate_keys(length):
        # Point at the global variables
        global public_key, private_key

        # Check that keys are saved in the OS keychain
        # If not, then both keys will be created
        if public_key is None or private_key is None:
            keys = RSA.generate(length)  # AVOID: Setting the length to 4096, caused a failure on Windows (issue #105)

            # Get public and private keys, encode them with `base64`, and convert them from `bytes` to `string`
            public_key, private_key = keys.publickey().exportKey(), \
                                    keys.exportKey()
            public_key, private_key = public_key.decode("utf-8"), \
                                    private_key.decode("utf-8")

            # Set both keys in the OS keychain
            set_password(public_key_name, "key", public_key)
            set_password(private_key_name, "key", private_key)

    try:
        # On Windows, the length `2048` is causing a failure sometimes, `4096` is always causing a filure though
        # To avoid this, on Windows key's length is `1024`
        if system() == "Windows":
            raise Exception()

        generate_keys(int(getenv("RSA_KEY_LENGTH", 2048)))
    except:
        try:
            generate_keys(int(getenv("RSA_KEY_LENGTH", 1024)))
        except:
            pass
        pass

    # Print the public key
    print(public_key)
except:
    pass
