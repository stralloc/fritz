#include <stdio.h>

#define KEY_PRIV "geheimer_schluessel.key"
#define KEY_PRIV_WARNING "ACHTUNG: DEN INHALT DIESER DATEI NIEMALS WEITERGEBEN, ES IST DEIN GEHEIMER SCHL�SSEL."
#define KEY_PUB "oeffentlicher_schluessel.key"
#define KEYFILE_PATH_STORE "schluesseldatei.txt"
#define KEYFILE_EMPTY_TEXT "[Keine Schl�sseldatei ausgew�hlt]"
#define KEY_PUB_TXT "Eigener Schl�ssel"
#define NEUER_KEY_TXT "Neuen Schl�ssel anlegen"
#define BUTTON_ENCR "Verschl�sseln"
#define BUTTON_DECR "Entschl�sseln"
#define ERROR_CRYPTO_BOX "Fehler beim Verschl�sseln."
#define ERROR_CRYPTO_BOX_OPEN "Entschl�sseln des Textes nicht m�glich.\n\n" \
"Solltest du den Text entschl�sseln wollen, dann ist es sehr wahrscheinlich, dass der verschl�sselte Text auf dem Weg zu dir ver�ndert wurde, oder du den falschen Schl�ssel ausgew�hlt hast.\n\n" \
"Wenn du den Text verschl�sseln wolltest, h�nge bitte ein Leerzeichen ran, damit dieser als Text zum Verschl�sseln erkannt wird."

#define ERROR_CRYPTO_BOX_OPEN_FILE "Entschl�sseln der Datei nicht m�glich.\n\n" \
"Es ist sehr wahrscheinlich, dass die verschl�sselte Datei auf dem Weg zu dir ver�ndert wurde, oder du den falschen Schl�ssel ausgew�hlt hast."

char *password_errors[] = {
"Kennwort ok.",
"Kennwort muss mindestens 10 Zeichen lang sein.",
"Kennwort enth�lt nicht genug kleine Buchstaben.",
"Kennwort enth�lt nicht genug Gro�buchstaben.",
"Kennwort enth�lt nicht genug Zahlen.",
"Kennwort enth�lt nicht genug Sonderzeichen.",
"Kennw�rter stimmen nicht �berein.",
"Kennwort entspricht dem alten Kennwort.",
NULL};
	
#define MSG_ERROR "Fehler"

#define MSG_OUT_OF_MEM "Zu wenig Hauptspeicher."
#define MSG_OUT_OF_MEM_CAN_NOT_START "Zu wenig Hauptspeicher, Programm kann nicht gestartet werden."

#define MSG_CREATE "Erstellen"
#define MSG_COPY "Kopieren"

#define MSG_ERROR_ONLY_FILE "Es kann nur eine Datei verschl�sselt werden."

#define MSG_MESSAGE_TO_LONG "Deine Eingabe ist zum Verschl�sseln zu lang und wurde um einige Bytes gek�rzt."
#define MSG_MESSAGE_TO_LONG_TITLE "Eingabe zu lang"

#define MSG_CRYPTO_TEST_ERROR "Der Selbsttest der Krypto-Funktionen ist fehlgeschlagen. Bitte lade dir eine neue Version von fritz auf "URL" "

// FILES
#define MSG_DEST_FILE_EXISTS_OVERWRITE "Zieldatei %s existiert bereits, soll diese �berschrieben werden?"
#define MSG_DEST_FILE_OVERWRITE "Zieldatei �berschreiben?"
#define MSG_FILE_DECRYPT_WITH_KEY "Datei %s mit dem Schl�ssel %s entschl�sseln?"
#define MSG_FILE_ENCRYPT_WITH_KEY "Datei %s mit dem Schl�ssel %s verschl�sseln?"
#define MSG_FILE_DECRYPT "Datei entschl�sseln"
#define MSG_FILE_ENCRYPT "Datei verschl�sseln"

#define MSG_WRITE_ERROR "Fehler beim Schreiben."

#define MSG_CAN_NOT_CREATE_DEST_FILE "Zieldatei %s kann nicht angelegt werden."
#define MSG_CAN_NOT_READ_SRC_FILE "Quelldatei %s kann nicht gelesen werden."

#define MSG_FILENAME_TO_LONG "Dateiname konnte nicht verschl�sselt werden, da bei Windows der Pfad einer Datei maximal %d Zeichen lang sein darf.\n\nDie verschl�sselte Datei wird als %s.fritz gespeichert."
#define MSG_PATH_TO_LONG "Pfad zu lang"

// KEYS + KEYFILES
#define MSG_READ_KEYFILE "Lese Schl�sseldatei"
#define MSG_CAN_NOT_READ_KEYFILE "Schl�sseldatei kann nicht gelesen werden."	
	
#define MSG_NO_KEY_SELECTED "Es ist kein Schl�ssel ausgew�hlt."
#define MSG_CAN_NOT_LOAD_KEY "Schl�ssel %s kann nicht geladen werden."

#define MSG_KEYFILE_TITLE "Schl�sseldatei"
#define MSG_KEYFILE "Um die Sicherheit deines geheimen Schl�ssels weiter zu erh�hen, kann dein Kennwort zus�tzlich mit einer Schl�sseldatei verkn�pft werden.\n\nBeachte bitte, dass die Schl�sseldatei niemals ver�ndert oder verschoben werden darf.\n\nUm die Verkn�pfung mit einer Schl�sseldatei wieder zu entfernen, �ndere dein Kennwort ohne Angabe einer Schl�sseldatei."

#define MSG_KEYFILE_CAN_NOT_OPEN "Die Datei "KEYFILE_PATH_STORE" kann nicht ge�ffnet werden."
#define MSG_KEYFILE_ERROR "Fehler in Datei "KEYFILE_PATH_STORE"."

#define MSG_REMOVE_KEY_FROM "Schl�ssel von %s endg�ltig l�schen?"
#define MSG_REMOVE_KEY "Schl�ssel endg�ltig l�schen?"

#define MSG_REMOVE_KEY_ERROR "Fehler beim L�schen des Schl�ssels."

#define MSG_RANDOM_KEY_COPIED "Achtung: Du versuchst einen zuf�lligen Schl�ssel weiterzugeben.\n\nZuf�llige Schl�ssel sind dazu gedacht, Dateien sicher abzulegen. Da jedoch nur du mit deinem zuf�lligen Schl�ssel und deinem privaten Schl�ssel diese Dateien entschl�sseln kannst, macht es keinen Sinn, diesen zuf�lligen Schl�ssel weiterzugeben."
#define MSG_RANDOM_KEY "Zuf�lliger Schl�ssel kopiert"

#define MSG_KEY_EXISTS "Schl�ssel existiert bereits, soll er �berschrieben werden?"
#define MSG_OVERWRITE "�berschreiben?"
#define MSG_KEY_CORRUPT "Schl�ssel ist fehlerhaft und kann nicht gespeichert werden."
#define MSG_KEY_NAME_CORRUPT "Schl�ssel kann nicht gespeichert werden.\n\nZeichen wie \\ oder / d�rfen im Namen nicht verwendet werden."

#define MSG_KEYS_NOT_FOUND "Eigene Schl�ssel wurden nicht gefunden, beim Fortfahren wird ein neues Schl�sselpaar angelegt."
#define MSG_KEYS_NOT_FOUND_TITLE "Eigene Schl�ssel nicht gefunden"

// PASSWORD
#define MSG_NEW_PASSWORD "Neues Kennwort"
#define MSG_NEW_PASSWORD_KEYFILE "Neues Kennwort und Schl�sseldatei"
#define MSG_INSERT_NEW_PASSWORD "Neues Kennwort eingeben"
#define MSG_INSERT_PASSWORD "Kennwort eingeben"
#define MSG_WRONG_PASSWORD "Falsches Kennwort."
#define MSG_PASSWORD_RULES "Das neue Kennwort muss mindestens %d Zeichen lang sein, es m�ssen jeweils mindestens %d kleine Buchstaben, gro�e Buchstaben, Sonderzeichen und Zahlen enthalten sein. Das neue Kennwort muss zur Wiederholung zweimal eingegeben werden."

#define MSG_PASSWORD_CHANGED_NO_KEYFILE "Kennwort erfolgreich ge�ndert. Es ist keine Schl�sseldatei hinterlegt."
#define MSG_PASSWORD_CHANGED_KEYFILE "Kennwort erfolgreich ge�ndert. Bitte die hinterlegte Schl�sseldatei nicht mehr ver�ndern, da dein geheimer Schl�ssel sonst nicht mehr ge�ffnet werden kann."

#define MSG_PASSWORD_TO_OLD "Das Kennwort f�r deinen geheimen Schl�ssel ist �lter als 100 Tage und muss ge�ndert werden."
#define MSG_PASSWORD_TO_OLD_TITLE "Kennwort abgelaufen"

// Buttons
#define TXT_MANAGE "Verwalten"
#define TXT_ENCRYPT "Verschl�sseln"
#define TXT_DELETE "L�schen"
#define TXT_COPY "Kopieren"
#define TXT_KEYRING "Schl�sselbund"
#define TXT_MORE_INFOS "Mehr Infos unter"

#define DIALOG_MANAGE_KEYS_TITLE "Schl�ssel verwalten"
#define TXT_CHANGE_PASSWORD_KEYFILE "Kennwort und Schl�sseldatei �ndern"
#define TXT_SAVE "Speichern"
#define TXT_ABORT "Abbrechen"
#define TXT_NAME "Name"
#define TXT_KEYS "Schl�ssel"
#define TXT_NEW_PASSWORD "Neues Kennwort"
#define TXT_REPEAT_NEW_PASSWORD "Neues Kennwort wiederholen"
#define TXT_OK "OK"
#define TXT_KEYFILE "Schl�sseldatei"
#define TXT_CHANGE "�ndern"

#define TXT_PASSWORD_FOR_PRIVATE_KEY "Bitte das Kennwort f�r den geheimen Schl�ssel eingeben"