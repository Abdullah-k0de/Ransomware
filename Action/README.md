### Action Component
The `client-encrypt.py` file is the encryption component. Save it in the server-type-arch folder in the github (or the payload setup.sh will have to be changed). This also generates the GUI to enter the password

The `client-decrypt-gui.py` is the decryption component that decrypts using the password given by the victim.

The `setup.sh` file has all the commands to download, initialize the environment, and run the attacks. This is the file that will be downloaded by the Rubber Ducky to run the setup in the background process.

The `store-credentials.ts` and `verify-password.ts` are supabase edge functions that has to be deployed and are helper functions for encryption and decryption component respectively.