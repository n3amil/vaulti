// Translations. English text is the key; other languages map it to their text.
// Missing keys fall back to English. `{name}` placeholders are filled from vars.
// In static HTML, elements carry data-i18n (text), data-i18n-placeholder,
// data-i18n-title, data-i18n-alt or data-i18n-aria-label. `**x**` renders x bold.

const LANG_KEY = 'vaulti.lang';
export const LANGUAGES = { en: 'English', de: 'Deutsch' };

const de = {
  // setup / auth
  'Create your vault': 'Tresor anlegen',
  'Your master password encrypts everything. It never leaves this device.':
    'Dein Master-Passwort verschlüsselt alles. Es verlässt dieses Gerät nie.',
  'Master password': 'Master-Passwort',
  'Repeat': 'Wiederholen',
  'Create vault': 'Tresor anlegen',
  'I already use Vaulti on another device': 'Ich nutze Vaulti schon auf einem anderen Gerät',
  'Add this device': 'Dieses Gerät hinzufügen',
  'On your other device open **Devices → Pair new device** and copy the pairing code here. Both devices need to be online.':
    'Öffne auf deinem anderen Gerät **Geräte → Neues Gerät koppeln** und kopiere den Kopplungscode hierher. Beide Geräte müssen online sein.',
  'On your other device open **Devices → Pair new device** and scan the QR code shown there. Both devices need to be online.':
    'Öffne auf deinem anderen Gerät **Geräte → Neues Gerät koppeln** und scanne den dort angezeigten QR-Code. Beide Geräte müssen online sein.',
  'Scan QR code': 'QR-Code scannen',
  'Pairing code': 'Kopplungscode',
  'Name for this device': 'Name für dieses Gerät',
  'e.g. Work laptop': 'z. B. Arbeitslaptop',
  'Confirm on your other device that it shows:': 'Bestätige auf deinem anderen Gerät, dass dort Folgendes steht:',
  'Received your vault. Unlock it with your master password.':
    'Dein Tresor ist angekommen. Entsperre ihn mit deinem Master-Passwort.',
  'Connect': 'Verbinden',
  'Connecting…': 'Verbinde…',
  'Waiting for confirmation…': 'Warte auf Bestätigung…',
  'Back': 'Zurück',
  '‹ Back': '‹ Zurück',
  'Your backup code': 'Dein Wiederherstellungscode',
  'If you forget your master password, this code is the only way back in. Write it down and keep it somewhere safe and offline. It will not be shown again.':
    'Wenn du dein Master-Passwort vergisst, kommst du nur mit diesem Code wieder hinein. Schreib ihn auf und bewahre ihn sicher und offline auf. Er wird nicht noch einmal angezeigt.',
  'I have written down my backup code': 'Ich habe meinen Wiederherstellungscode aufgeschrieben',
  'Continue': 'Weiter',
  'Vaulti is locked': 'Vaulti ist gesperrt',
  'Unlock': 'Entsperren',
  'Forgot master password?': 'Master-Passwort vergessen?',
  'Recover vault': 'Tresor wiederherstellen',
  'Enter your backup code and choose a new master password. You will get a new backup code afterwards.':
    'Gib deinen Wiederherstellungscode ein und wähle ein neues Master-Passwort. Danach bekommst du einen neuen Wiederherstellungscode.',
  'Backup code': 'Wiederherstellungscode',
  'New master password': 'Neues Master-Passwort',
  'Recover': 'Wiederherstellen',
  'Passwords do not match': 'Die Passwörter stimmen nicht überein',
  'Camera permission is needed to scan the code. You can paste it instead.':
    'Zum Scannen wird die Kamera-Berechtigung benötigt. Du kannst den Code stattdessen auch einfügen.',
  "That QR code isn't a Vaulti pairing code": 'Dieser QR-Code ist kein Vaulti-Kopplungscode',
  'This device is now paired': 'Dieses Gerät ist jetzt gekoppelt',
  'Failed to start: {err}': 'Start fehlgeschlagen: {err}',

  // main
  'Done': 'Fertig',
  'All items': 'Alle Einträge',
  'Collections': 'Sammlungen',
  'New collection': 'Neue Sammlung',
  'Devices': 'Geräte',
  'Contacts': 'Kontakte',
  'Settings': 'Einstellungen',
  'Lock': 'Sperren',
  'Sync now': 'Jetzt synchronisieren',
  'Starting…': 'Starte…',
  'Collections and menu': 'Sammlungen und Menü',
  'Search': 'Suchen',
  'New': 'Neu',
  'Share': 'Teilen',
  'Edit': 'Bearbeiten',
  'No entries yet.': 'Noch keine Einträge.',
  'No matches.': 'Keine Treffer.',
  'Select an entry': 'Wähle einen Eintrag',
  'shared': 'geteilt',
  'Shared by {name} · view only': 'Geteilt von {name} · nur ansehen',
  'Shared by {name} · you can edit': 'Geteilt von {name} · du kannst bearbeiten',
  'Shared with {names}': 'Geteilt mit {names}',
  'Owner': 'Besitzer',
  'Can edit': 'Kann bearbeiten',
  'Can view': 'Kann ansehen',
  'just now': 'gerade eben',
  '{n} min ago': 'vor {n} Min.',

  // detail
  'Username': 'Benutzername',
  'Password': 'Passwort',
  'One-time code': 'Einmalcode',
  'Website': 'Website',
  'Notes': 'Notizen',
  'Show': 'Anzeigen',
  'Hide': 'Verbergen',
  'Copy': 'Kopieren',
  'Delete': 'Löschen',
  'View only: this collection is shared with you read-only.':
    'Nur ansehen: Diese Sammlung wurde mit dir schreibgeschützt geteilt.',
  'Updated {date}': 'Geändert {date}',
  'Password copied, clears in 30 s': 'Passwort kopiert, wird in 30 s gelöscht',
  'Code copied, clears in 30 s': 'Code kopiert, wird in 30 s gelöscht',
  '{label} copied': '{label} kopiert',
  'Delete "{title}"? This can\'t be undone.': '„{title}“ löschen? Das kann nicht rückgängig gemacht werden.',
  'Entry deleted': 'Eintrag gelöscht',

  // entry dialog
  'New entry': 'Neuer Eintrag',
  'Edit entry': 'Eintrag bearbeiten',
  'Title': 'Titel',
  'Generate': 'Erzeugen',
  'Passphrase': 'Passphrase',
  'Length': 'Länge',
  'Avoid look-alikes (0 O 1 l I)': 'Ähnliche Zeichen vermeiden (0 O 1 l I)',
  'Words': 'Wörter',
  'Separator': 'Trennzeichen',
  'Hyphen  -': 'Bindestrich  -',
  'Space': 'Leerzeichen',
  'Period  .': 'Punkt  .',
  'Underscore  _': 'Unterstrich  _',
  'Hash  #': 'Raute  #',
  'None': 'Keins',
  'Custom…': 'Eigenes…',
  'e.g. +': 'z. B. +',
  'Capitalize words': 'Wörter großschreiben',
  'Add a number': 'Zahl hinzufügen',
  'Use': 'Übernehmen',
  'Weak': 'Schwach',
  'Fair': 'Mittel',
  'Strong': 'Stark',
  'Very strong': 'Sehr stark',
  '{label} · ~{bits} bits': '{label} · ~{bits} Bit',
  'One-time code (TOTP)': 'Einmalcode (TOTP)',
  'Scan': 'Scannen',
  'Secret or otpauth:// link': 'Geheimnis oder otpauth://-Link',
  '✓ Valid': '✓ Gültig',
  '✓ Valid ({label})': '✓ Gültig ({label})',
  'Collection': 'Sammlung',
  'Cancel': 'Abbrechen',
  'Save': 'Speichern',
  'Saved': 'Gespeichert',
  'Entry added': 'Eintrag hinzugefügt',

  // collections
  'Edit collection': 'Sammlung bearbeiten',
  'Name': 'Name',
  'Delete "{name}" and its {n} entries? This can\'t be undone.':
    '„{name}“ und die {n} Einträge darin löschen? Das kann nicht rückgängig gemacht werden.',
  'Delete "{name}"?': '„{name}“ löschen?',
  'Collection deleted': 'Sammlung gelöscht',
  'Personal': 'Persönlich',

  // settings
  'Language': 'Sprache',
  'Automatic': 'Automatisch',
  'Your name': 'Dein Name',
  'Shown to people you share collections with.': 'Wird Personen angezeigt, mit denen du Sammlungen teilst.',
  'Name saved': 'Name gespeichert',
  'Change master password': 'Master-Passwort ändern',
  'Your backup code stays the same.': 'Dein Wiederherstellungscode bleibt gleich.',
  'Change password': 'Passwort ändern',
  'Master password changed': 'Master-Passwort geändert',
  'Backup': 'Sicherung',
  'Save all collections and entries to a file encrypted with a backup password. Keep it somewhere safe, e.g. on a USB stick.':
    'Speichert alle Sammlungen und Einträge in einer Datei, die mit einem Sicherungspasswort verschlüsselt ist. Bewahre sie sicher auf, z. B. auf einem USB-Stick.',
  'Backup password': 'Sicherungspasswort',
  'Export backup…': 'Sicherung exportieren…',
  'Importing adds entries to collections with the same name; entries you already have are skipped.':
    'Beim Import landen Einträge in Sammlungen mit gleichem Namen; vorhandene Einträge werden übersprungen.',
  'Import backup…': 'Sicherung importieren…',
  'Vaulti backup': 'Vaulti-Sicherung',
  'Backup saved': 'Sicherung gespeichert',
  'Imported {n} entries': '{n} Einträge importiert',
  'Imported {n} entries, {skipped} already there': '{n} Einträge importiert, {skipped} waren schon vorhanden',
  'Create a new backup code. Your current one stops working.':
    'Erstellt einen neuen Wiederherstellungscode. Dein bisheriger funktioniert dann nicht mehr.',
  'New backup code': 'Neuer Wiederherstellungscode',
  'Create a new backup code? Your current code will stop working.':
    'Neuen Wiederherstellungscode erstellen? Dein bisheriger Code funktioniert dann nicht mehr.',
  'Create new code': 'Neuen Code erstellen',
  'About': 'Info',
  'Locks automatically after 5 minutes of inactivity. Copied passwords are cleared from the clipboard after 30 seconds.':
    'Sperrt sich nach 5 Minuten Inaktivität automatisch. Kopierte Passwörter werden nach 30 Sekunden aus der Zwischenablage gelöscht.',
  'Vault file:': 'Tresordatei:',
  'Close': 'Schließen',

  // sharing
  'Share "{name}"': '„{name}“ teilen',
  "Members get the collection on their devices the next time you're both online.":
    'Mitglieder bekommen die Sammlung auf ihre Geräte, sobald ihr das nächste Mal beide online seid.',
  'Add someone': 'Person hinzufügen',
  'Add': 'Hinzufügen',
  'Add people under **Contacts** first, then share with them here.':
    'Füge Personen zuerst unter **Kontakte** hinzu und teile dann hier mit ihnen.',
  'Everyone in your contacts is already a member.': 'Alle deine Kontakte sind schon Mitglied.',
  'Removing someone stops future updates. They keep what they already received, so change those passwords if needed.':
    'Wer entfernt wird, bekommt keine Updates mehr, behält aber, was schon angekommen ist. Ändere diese Passwörter bei Bedarf.',
  '{name} (you)': '{name} (du)',
  'Remove': 'Entfernen',
  'Remove {name} from this collection? They keep what they already synced.':
    '{name} aus dieser Sammlung entfernen? Bereits Synchronisiertes bleibt bei der Person.',
  '{name} removed': '{name} entfernt',
  'Shared. It arrives on their devices when you are both online.':
    'Geteilt. Es kommt auf den Geräten an, sobald ihr beide online seid.',

  // devices
  'Your devices': 'Deine Geräte',
  "Devices sync directly with each other whenever they're online at the same time.":
    'Geräte synchronisieren sich direkt miteinander, wann immer sie gleichzeitig online sind.',
  'Pair new device': 'Neues Gerät koppeln',
  'Pair a new device': 'Ein neues Gerät koppeln',
  'On the new device install Vaulti, choose **I already use Vaulti on another device** and scan the QR code (or paste the code). It works once and expires in 10 minutes.':
    'Installiere Vaulti auf dem neuen Gerät, wähle **Ich nutze Vaulti schon auf einem anderen Gerät** und scanne den QR-Code (oder füge den Code ein). Er funktioniert einmal und läuft nach 10 Minuten ab.',
  'Pairing QR code': 'Kopplungs-QR-Code',
  'Copy code': 'Code kopieren',
  'Waiting for the other device…': 'Warte auf das andere Gerät…',
  'wants to join. Check that it shows this code:': 'möchte beitreten. Prüfe, ob dort dieser Code steht:',
  "Doesn't match": 'Stimmt nicht überein',
  'Codes match, pair': 'Codes stimmen, koppeln',
  'This device': 'Dieses Gerät',
  'Online, in sync': 'Online, synchron',
  'Offline': 'Offline',
  'Not seen yet': 'Noch nicht gesehen',
  'Rename': 'Umbenennen',
  'Remove "{name}"? It stops syncing. Its copy of the vault stays encrypted with your master password.':
    '„{name}“ entfernen? Es synchronisiert dann nicht mehr. Seine Kopie des Tresors bleibt mit deinem Master-Passwort verschlüsselt.',
  'Preparing…': 'Wird vorbereitet…',
  'Pairing code copied': 'Kopplungscode kopiert',
  'Device connected, waiting for your confirmation.': 'Gerät verbunden, warte auf deine Bestätigung.',
  'Pairing rejected. Start again for a new code.': 'Kopplung abgelehnt. Starte neu für einen neuen Code.',
  'Sending your vault…': 'Sende deinen Tresor…',
  'Paired "{name}"': '„{name}“ gekoppelt',

  // contacts
  'People you can share collections with. Exchange contact cards (e.g. by chat or email), then compare fingerprints by phone or in person.':
    'Personen, mit denen du Sammlungen teilen kannst. Tauscht Kontaktkarten aus (z. B. per Chat oder E-Mail) und vergleicht dann die Fingerabdrücke am Telefon oder persönlich.',
  'Your contact card': 'Deine Kontaktkarte',
  'Fingerprint:': 'Fingerabdruck:',
  'Copy my card': 'Meine Karte kopieren',
  'Add a contact': 'Kontakt hinzufügen',
  'Check that this fingerprint matches what they see under Contacts → Your contact card.':
    'Prüfe, ob dieser Fingerabdruck mit dem übereinstimmt, was die Person unter Kontakte → Deine Kontaktkarte sieht.',
  'Check card': 'Karte prüfen',
  'Add contact': 'Kontakt hinzufügen',
  'Contact added': 'Kontakt hinzugefügt',
  'Remove {name} from your contacts? Collections you shared stay shared until you remove them there.':
    '{name} aus deinen Kontakten entfernen? Geteilte Sammlungen bleiben geteilt, bis du die Person dort entfernst.',
  'Contact card copied. Send it to the person you want to share with.':
    'Kontaktkarte kopiert. Schick sie der Person, mit der du teilen möchtest.',

  // sync status
  'Only this device': 'Nur dieses Gerät',
  'Synced {ago} · {online}/{total} online': 'Sync {ago} · {online}/{total} online',
  'Other devices offline': 'Andere Geräte offline',
  'Syncing…': 'Synchronisiere…',

  // messages from the Rust side (see translateError)
  'Master password must be at least 8 characters': 'Das Master-Passwort muss mindestens 8 Zeichen lang sein',
  'A vault already exists': 'Es gibt bereits einen Tresor',
  'Sync is not running': 'Die Synchronisierung läuft nicht',
  'Title is required': 'Ein Titel ist erforderlich',
  'Wrong master password': 'Falsches Master-Passwort',
  "That doesn't look like a backup code": 'Das sieht nicht nach einem Wiederherstellungscode aus',
  'Backup code is not valid': 'Der Wiederherstellungscode ist ungültig',
  'Name is required': 'Ein Name ist erforderlich',
  "You can't delete your last collection": 'Die letzte Sammlung kann nicht gelöscht werden',
  'Wrong backup password or damaged file': 'Falsches Sicherungspasswort oder beschädigte Datei',
  'Field is empty': 'Das Feld ist leer',
  "That isn't a valid contact card": 'Das ist keine gültige Kontaktkarte',
  "That's your own card": 'Das ist deine eigene Karte',
  "that's your own card": 'Das ist deine eigene Karte',
  'not a vaulti pairing ticket': 'Das ist kein Vaulti-Kopplungscode',
  'no pairing request from that device (expired?)': 'Keine Kopplungsanfrage von diesem Gerät (abgelaufen?)',
  'timed out connecting': 'Zeitüberschreitung beim Verbinden',
  'sync timed out': 'Zeitüberschreitung bei der Synchronisierung',
  'timed out connecting to the other device': 'Zeitüberschreitung beim Verbinden mit dem anderen Gerät',
  'timed out waiting for confirmation': 'Zeitüberschreitung beim Warten auf Bestätigung',
  'pairing refused: pairing code is invalid or expired': 'Kopplung abgelehnt: Der Kopplungscode ist ungültig oder abgelaufen',
  'pairing refused: not confirmed on the other device': 'Kopplung abgelehnt: Auf dem anderen Gerät nicht bestätigt',
  'vault is locked': 'Der Tresor ist gesperrt',
  'decryption failed (wrong password/backup code or corrupted data)':
    'Entschlüsselung fehlgeschlagen (falsches Passwort/falscher Code oder beschädigte Daten)',
  'invalid backup code format': 'Ungültiges Format des Wiederherstellungscodes',
  'collection not found': 'Sammlung nicht gefunden',
  'entry not found': 'Eintrag nicht gefunden',
  'contact not found': 'Kontakt nicht gefunden',
  'this vault was copied from another device; finish pairing first':
    'Dieser Tresor wurde von einem anderen Gerät kopiert; schließe zuerst die Kopplung ab',
  'not a vaulti contact card': 'Das ist keine Vaulti-Kontaktkarte',
  'bad contact card': 'Ungültige Kontaktkarte',
  'not a Vaulti backup': 'Das ist keine Vaulti-Sicherung',
  'not a Vaulti backup file': 'Das ist keine Vaulti-Sicherungsdatei',
  'you can only view the target collection': 'Die Zielsammlung darfst du nur ansehen',
  "can't remove this device": 'Dieses Gerät kann nicht entfernt werden',
  'only the owner can change this collection': 'Nur der Besitzer kann diese Sammlung ändern',
  "the owner can't be removed": 'Der Besitzer kann nicht entfernt werden',
  'you can only view this collection': 'Diese Sammlung darfst du nur ansehen',
  'choose at least one character type': 'Wähle mindestens eine Zeichenart',
  'length must be between 4 and 128': 'Die Länge muss zwischen 4 und 128 liegen',
  'use between 3 and 20 words': 'Verwende 3 bis 20 Wörter',
  'separator can be at most 3 characters': 'Das Trennzeichen darf höchstens 3 Zeichen haben',
  'empty secret': 'Das Geheimnis ist leer',
  'secret is not valid base32': 'Das Geheimnis ist kein gültiges Base32',
  'only time-based (totp) codes are supported': 'Nur zeitbasierte (TOTP) Codes werden unterstützt',
  'unsupported algorithm': 'Nicht unterstützter Algorithmus',
  'invalid digits': 'Ungültige Stellenzahl',
  'invalid period': 'Ungültiger Zeitraum',
  'digits must be 6 to 8': 'Die Stellenzahl muss 6 bis 8 sein',
  'period must be 1 to 300 seconds': 'Der Zeitraum muss 1 bis 300 Sekunden sein',
  'the link has no secret': 'Der Link enthält kein Geheimnis',
};

const DICTS = { de };

function detect() {
  for (const l of navigator.languages ?? [navigator.language]) {
    const code = String(l).slice(0, 2).toLowerCase();
    if (code in LANGUAGES) return code;
  }
  return 'en';
}

let pref = 'auto';
try {
  pref = localStorage.getItem(LANG_KEY) || 'auto';
} catch {}
export let lang = pref in LANGUAGES ? pref : detect();

export const langPref = () => pref;

export function setLangPref(value) {
  pref = value;
  try {
    if (value === 'auto') localStorage.removeItem(LANG_KEY);
    else localStorage.setItem(LANG_KEY, value);
  } catch {}
  lang = value in LANGUAGES ? value : detect();
  translatePage();
}

export function t(key, vars = {}) {
  const s = DICTS[lang]?.[key] ?? key;
  return s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

// Messages from the backend arrive in English, sometimes with a prefix.
const PREFIXES = ['malformed data: ', 'not allowed: ', 'TOTP: '];
export function translateError(err) {
  let msg = String(err?.message ?? err);
  for (const p of PREFIXES) if (msg.startsWith(p)) msg = msg.slice(p.length);
  return t(msg);
}

// Sets text with `**bold**` parts, without innerHTML.
export function setRich(el, text) {
  el.replaceChildren(
    ...text.split(/\*\*(.+?)\*\*/).map((part, i) => (i % 2 ? Object.assign(document.createElement('b'), { textContent: part }) : part)),
  );
}

const ATTRS = ['placeholder', 'title', 'alt', 'aria-label'];

export function translatePage(root = document) {
  document.documentElement.lang = lang;
  for (const el of root.querySelectorAll('[data-i18n]')) setRich(el, t(el.dataset.i18n));
  for (const a of ATTRS) {
    for (const el of root.querySelectorAll(`[data-i18n-${a}]`)) el.setAttribute(a, t(el.getAttribute(`data-i18n-${a}`)));
  }
}
