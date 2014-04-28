#include <stdio.h>

#define KEY_PRIV "private_key.key"
#define KEY_PRIV_WARNING "ATTENTION: NEVER PASS ON THE CONTENT OF THIS FILE, BECAUSE IT IS YOUR PRIVATE KEY."
#define KEY_PUB "public_key.key"
#define KEYFILE_PATH_STORE "keyfile.txt"
#define KEYFILE_EMPTY_TEXT "[No keyfile selected]"
#define KEY_PUB_TXT "My public key"
#define NEUER_KEY_TXT "Create new key"
#define BUTTON_ENCR "Encrypt" // VERSCHLÜSSELN
#define BUTTON_DECR "Decrypt" // ENTSCHLÜSSELN
#define ERROR_CRYPTO_BOX "Encryption failure"
#define ERROR_CRYPTO_BOX_OPEN "Decryption not possible.\n\n" \
"If you decryption failed, it could be possible, that you selected the wrong key or your encrypted text was manipulated.\n\n" \
"If you encryption failed, please attach a whitespace or a punctuation mark at the end of your text."

#define ERROR_CRYPTO_BOX_OPEN_FILE "File decryption not possible.\n\n" \
"It could be possible, that you selected the wrong key or your encrypted file was manipulated."

char *password_errors[] = {
"Password ok.",
"Password must be at least 10 characters.",
"Password contains not enough small letters.",
"Password contains not enough capital letters.",
"Password contains not enough numbers.",
"Password contains not enough special character.",
"Passwords do not match.",
"Password is equal to the old password.",
NULL};
	
#define MSG_ERROR "Error"

#define MSG_OUT_OF_MEM "Out of memory"
#define MSG_OUT_OF_MEM_CAN_NOT_START "Out of memory, program can't start."

#define MSG_CREATE "Create"
#define MSG_COPY "Copy"

#define MSG_ERROR_ONLY_FILE "You can only encrypt one file."

#define MSG_MESSAGE_TO_LONG "Your input is to long to encrypt and was cut."
#define MSG_MESSAGE_TO_LONG_TITLE "Input to long"

#define MSG_CRYPTO_TEST_ERROR "One of my selftests failed. Please download the newest version of fritz at "URL" "

// FILES
#define MSG_DEST_FILE_EXISTS_OVERWRITE "Destination file %s exists, overwrite?"
#define MSG_DEST_FILE_OVERWRITE "Overwrite?"
#define MSG_FILE_DECRYPT_WITH_KEY "Decrypt file %s with key %s?"
#define MSG_FILE_ENCRYPT_WITH_KEY "Encrypt file %s with key %s?"
#define MSG_FILE_DECRYPT "Decrypt file"
#define MSG_FILE_ENCRYPT "Encrypt file"

#define MSG_WRITE_ERROR "Error writing."

#define MSG_CAN_NOT_CREATE_DEST_FILE "Can't create destination file %s"
#define MSG_CAN_NOT_READ_SRC_FILE "Can't read source file %s"

#define MSG_FILENAME_TO_LONG "Filename can't encrypt. Your OS can only handle %d character paths. The encrypted file is saved as %s.fritz"

#define MSG_PATH_TO_LONG "Path to long"

// KEYS + KEYFILES
#define MSG_READ_KEYFILE "Read keyfile"
#define MSG_CAN_NOT_READ_KEYFILE "Can't read keyfile"	
	
#define MSG_NO_KEY_SELECTED "No key selected."
#define MSG_CAN_NOT_LOAD_KEY "Can't load key %s"

#define MSG_KEYFILE_TITLE "Keyfile"
#define MSG_KEYFILE "To increase the security of your secret key, your password can be connected with a keyfile.\n\nThe key file must never be changed or moved. To disconnect your password with the keyfile, change your password without a keyfile."

#define MSG_KEYFILE_CAN_NOT_OPEN "Can't open file "KEYFILE_PATH_STORE""
#define MSG_KEYFILE_ERROR "Error in file "KEYFILE_PATH_STORE""

#define MSG_REMOVE_KEY_FROM "Permanently delete key %s?"
#define MSG_REMOVE_KEY "Permanently delete key?"

#define MSG_REMOVE_KEY_ERROR "Can't delete key."

#define MSG_RANDOM_KEY_COPIED "Attention: Don't pass a random key. \n\nWith a random key you can save a file securely. Only you can decrypt these securely saved files with your random key and your private key, so it makes no sense to pass this random key."
#define MSG_RANDOM_KEY "Random key copied"

#define MSG_KEY_EXISTS "Key exists, overwrite?"
#define MSG_OVERWRITE "Overwrite?"
#define MSG_KEY_CORRUPT "Key is damaged and can not be saved."
#define MSG_KEY_NAME_CORRUPT "Can't save key. Don't use characters like \\ or /."

#define MSG_KEYS_NOT_FOUND "No keypair found, press ok to continue. A new keypair will be created."
#define MSG_KEYS_NOT_FOUND_TITLE "No keypair found"

// PASSWORD
#define MSG_NEW_PASSWORD "New password"
#define MSG_NEW_PASSWORD_KEYFILE "New password and keyfile"
#define MSG_INSERT_NEW_PASSWORD "Enter new password"
#define MSG_INSERT_PASSWORD "Enter password"
#define MSG_WRONG_PASSWORD "Wrong password"
#define MSG_PASSWORD_RULES "The new password must be at least %d characters and must contain at least %d small letters, capital letters, special characters and numbers. Enter password twice."

#define MSG_PASSWORD_CHANGED_NO_KEYFILE "Password successfully changed. No keyfile used."
#define MSG_PASSWORD_CHANGED_KEYFILE "Password successfully changed. Don't change the keyfile path or content."

#define MSG_PASSWORD_TO_OLD "The password is older then 100 days and must be changed."
#define MSG_PASSWORD_TO_OLD_TITLE "Password expired"

// Buttons
#define TXT_MANAGE "Manage"
#define TXT_ENCRYPT "Encrypt"
#define TXT_DELETE "Delete"
#define TXT_COPY "Copy"
#define TXT_KEYRING "Keyring"
#define TXT_MORE_INFOS "More infos at"

#define DIALOG_MANAGE_KEYS_TITLE "Manage keys"
#define TXT_CHANGE_PASSWORD_KEYFILE "Change password and keyfile"
#define TXT_SAVE "Save"
#define TXT_ABORT "Abort"
#define TXT_NAME "Name"
#define TXT_KEYS "Keys"
#define TXT_NEW_PASSWORD "New password"
#define TXT_REPEAT_NEW_PASSWORD "New password again"
#define TXT_OK "OK"
#define TXT_KEYFILE "Keyfile"
#define TXT_CHANGE "Change"

#define TXT_PASSWORD_FOR_PRIVATE_KEY "Enter the password for your private key"