#include <stdio.h>

#define KEY_PRIV "geheimer_schluessel.key"
#define KEY_PRIV_WARNING "ACHTUNG: DEN INHALT DIESER DATEI NIEMALS WEITERGEBEN, ES IST DEIN GEHEIMER SCHLÜSSEL."
#define KEY_PUB "oeffentlicher_schluessel.key"
#define KEYFILE_PATH_STORE "schluesseldatei.txt"
#define KEYFILE_EMPTY_TEXT "[Keine Schlüsseldatei ausgewählt]"
#define KEY_PUB_TXT "Eigener Schlüssel"
#define NEUER_KEY_TXT "Neuen Schlüssel anlegen"
#define BUTTON_ENCR "Verschlüsseln"
#define BUTTON_DECR "Entschlüsseln"
#define ERROR_CRYPTO_BOX "Fehler beim Verschlüsseln."
#define ERROR_CRYPTO_BOX_OPEN "Entschlüsseln des Textes nicht möglich.\n\n" \
"Solltest du den Text entschlüsseln wollen, dann ist es sehr wahrscheinlich, dass der verschlüsselte Text auf dem Weg zu dir verändert wurde, oder du den falschen Schlüssel ausgewählt hast.\n\n" \
"Wenn du den Text verschlüsseln wolltest, hänge bitte ein Leerzeichen ran, damit dieser als Text zum Verschlüsseln erkannt wird."

#define ERROR_CRYPTO_BOX_OPEN_FILE "Entschlüsseln der Datei nicht möglich.\n\n" \
"Es ist sehr wahrscheinlich, dass die verschlüsselte Datei auf dem Weg zu dir verändert wurde, oder du den falschen Schlüssel ausgewählt hast."

char *password_errors[] = {
"Kennwort ok.",
"Kennwort muss mindestens 10 Zeichen lang sein.",
"Kennwort enthält nicht genug kleine Buchstaben.",
"Kennwort enthält nicht genug Großbuchstaben.",
"Kennwort enthält nicht genug Zahlen.",
"Kennwort enthält nicht genug Sonderzeichen.",
"Kennwörter stimmen nicht überein.",
"Kennwort entspricht dem alten Kennwort.",
NULL};
	
#define MSG_ERROR "Fehler"

#define MSG_OUT_OF_MEM "Zu wenig Hauptspeicher."
#define MSG_OUT_OF_MEM_CAN_NOT_START "Zu wenig Hauptspeicher, Programm kann nicht gestartet werden."

#define MSG_CREATE "Erstellen"
#define MSG_COPY "Kopieren"

#define MSG_ERROR_ONLY_FILE "Es kann nur eine Datei verschlüsselt werden."

#define MSG_MESSAGE_TO_LONG "Deine Eingabe ist zum Verschlüsseln zu lang und wurde um einige Bytes gekürzt."
#define MSG_MESSAGE_TO_LONG_TITLE "Eingabe zu lang"

#define MSG_CRYPTO_TEST_ERROR "Der Selbsttest der Krypto-Funktionen ist fehlgeschlagen. Bitte lade dir eine neue Version von fritz auf "URL" "

// FILES
#define MSG_DEST_FILE_EXISTS_OVERWRITE "Zieldatei %s existiert bereits, soll diese überschrieben werden?"
#define MSG_DEST_FILE_OVERWRITE "Zieldatei überschreiben?"
#define MSG_FILE_DECRYPT_WITH_KEY "Datei %s mit dem Schlüssel %s entschlüsseln?"
#define MSG_FILE_ENCRYPT_WITH_KEY "Datei %s mit dem Schlüssel %s verschlüsseln?"
#define MSG_FILE_DECRYPT "Datei entschlüsseln"
#define MSG_FILE_ENCRYPT "Datei verschlüsseln"

#define MSG_WRITE_ERROR "Fehler beim Schreiben."

#define MSG_CAN_NOT_CREATE_DEST_FILE "Zieldatei %s kann nicht angelegt werden."
#define MSG_CAN_NOT_READ_SRC_FILE "Quelldatei %s kann nicht gelesen werden."

#define MSG_FILENAME_TO_LONG "Dateiname konnte nicht verschlüsselt werden, da bei Windows der Pfad einer Datei maximal %d Zeichen lang sein darf.\n\nDie verschlüsselte Datei wird als %s.fritz gespeichert."
#define MSG_PATH_TO_LONG "Pfad zu lang"

// KEYS + KEYFILES
#define MSG_READ_KEYFILE "Lese Schlüsseldatei"
#define MSG_CAN_NOT_READ_KEYFILE "Schlüsseldatei kann nicht gelesen werden."	
	
#define MSG_NO_KEY_SELECTED "Es ist kein Schlüssel ausgewählt."
#define MSG_CAN_NOT_LOAD_KEY "Schlüssel %s kann nicht geladen werden."

#define MSG_KEYFILE_TITLE "Schlüsseldatei"
#define MSG_KEYFILE "Um die Sicherheit deines geheimen Schlüssels weiter zu erhöhen, kann dein Kennwort zusätzlich mit einer Schlüsseldatei verknüpft werden.\n\nBeachte bitte, dass die Schlüsseldatei niemals verändert oder verschoben werden darf.\n\nUm die Verknüpfung mit einer Schlüsseldatei wieder zu entfernen, ändere dein Kennwort ohne Angabe einer Schlüsseldatei."

#define MSG_KEYFILE_CAN_NOT_OPEN "Die Datei "KEYFILE_PATH_STORE" kann nicht geöffnet werden."
#define MSG_KEYFILE_ERROR "Fehler in Datei "KEYFILE_PATH_STORE"."

#define MSG_REMOVE_KEY_FROM "Schlüssel von %s endgültig löschen?"
#define MSG_REMOVE_KEY "Schlüssel endgültig löschen?"

#define MSG_REMOVE_KEY_ERROR "Fehler beim Löschen des Schlüssels."

#define MSG_RANDOM_KEY_COPIED "Achtung: Du versuchst einen zufälligen Schlüssel weiterzugeben.\n\nZufällige Schlüssel sind dazu gedacht, Dateien sicher abzulegen. Da jedoch nur du mit deinem zufälligen Schlüssel und deinem privaten Schlüssel diese Dateien entschlüsseln kannst, macht es keinen Sinn, diesen zufälligen Schlüssel weiterzugeben."
#define MSG_RANDOM_KEY "Zufälliger Schlüssel kopiert"

#define MSG_KEY_EXISTS "Schlüssel existiert bereits, soll er überschrieben werden?"
#define MSG_OVERWRITE "Überschreiben?"
#define MSG_KEY_CORRUPT "Schlüssel ist fehlerhaft und kann nicht gespeichert werden."
#define MSG_KEY_NAME_CORRUPT "Schlüssel kann nicht gespeichert werden.\n\nZeichen wie \\ oder / dürfen im Namen nicht verwendet werden."

#define MSG_KEYS_NOT_FOUND "Eigene Schlüssel wurden nicht gefunden, beim Fortfahren wird ein neues Schlüsselpaar angelegt."
#define MSG_KEYS_NOT_FOUND_TITLE "Eigene Schlüssel nicht gefunden"

// PASSWORD
#define MSG_NEW_PASSWORD "Neues Kennwort"
#define MSG_NEW_PASSWORD_KEYFILE "Neues Kennwort und Schlüsseldatei"
#define MSG_INSERT_NEW_PASSWORD "Neues Kennwort eingeben"
#define MSG_INSERT_PASSWORD "Kennwort eingeben"
#define MSG_WRONG_PASSWORD "Falsches Kennwort."
#define MSG_PASSWORD_RULES "Das neue Kennwort muss mindestens %d Zeichen lang sein, es müssen jeweils mindestens %d kleine Buchstaben, große Buchstaben, Sonderzeichen und Zahlen enthalten sein. Das neue Kennwort muss zur Wiederholung zweimal eingegeben werden."

#define MSG_PASSWORD_CHANGED_NO_KEYFILE "Kennwort erfolgreich geändert. Es ist keine Schlüsseldatei hinterlegt."
#define MSG_PASSWORD_CHANGED_KEYFILE "Kennwort erfolgreich geändert. Bitte die hinterlegte Schlüsseldatei nicht mehr verändern, da dein geheimer Schlüssel sonst nicht mehr geöffnet werden kann."

#define MSG_PASSWORD_TO_OLD "Das Kennwort für deinen geheimen Schlüssel ist älter als 100 Tage und muss geändert werden."
#define MSG_PASSWORD_TO_OLD_TITLE "Kennwort abgelaufen"

// Buttons
#define TXT_MANAGE "Verwalten"
#define TXT_ENCRYPT "Verschlüsseln"
#define TXT_DELETE "Löschen"
#define TXT_COPY "Kopieren"
#define TXT_KEYRING "Schlüsselbund"
#define TXT_MORE_INFOS "Mehr Infos unter"

#define DIALOG_MANAGE_KEYS_TITLE "Schlüssel verwalten"
#define TXT_CHANGE_PASSWORD_KEYFILE "Kennwort und Schlüsseldatei ändern"
#define TXT_SAVE "Speichern"
#define TXT_ABORT "Abbrechen"
#define TXT_NAME "Name"
#define TXT_KEYS "Schlüssel"
#define TXT_NEW_PASSWORD "Neues Kennwort"
#define TXT_REPEAT_NEW_PASSWORD "Neues Kennwort wiederholen"
#define TXT_OK "OK"
#define TXT_KEYFILE "Schlüsseldatei"
#define TXT_CHANGE "Ändern"

#define TXT_PASSWORD_FOR_PRIVATE_KEY "Bitte das Kennwort für den geheimen Schlüssel eingeben"