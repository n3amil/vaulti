// Friendly names for people, derived from their key fingerprint (like LocalSend's
// device names): "Brave Fox" / "Mutiger Fuchs". Same position in both languages,
// so the name only changes with the UI language, never between devices.
// Only 12 bits: a recognisable label, not a security check. Comparing in person
// is done by scanning the QR code; the full fingerprint stays under "Details".

import { lang } from './i18n.js';

// [English, German]. German animals are all masculine so "-er" adjectives fit.
const ADJECTIVES = [
  ['Brave', 'Mutiger'], ['Happy', 'Fröhlicher'], ['Quick', 'Schneller'], ['Clever', 'Kluger'],
  ['Calm', 'Ruhiger'], ['Wild', 'Wilder'], ['Gentle', 'Sanfter'], ['Bold', 'Kühner'],
  ['Proud', 'Stolzer'], ['Nimble', 'Flinker'], ['Bright', 'Heller'], ['Sunny', 'Sonniger'],
  ['Lively', 'Munterer'], ['Friendly', 'Freundlicher'], ['Cheeky', 'Frecher'], ['Wise', 'Weiser'],
  ['Quiet', 'Stiller'], ['Funny', 'Lustiger'], ['Eager', 'Eifriger'], ['Loyal', 'Treuer'],
  ['Skilful', 'Geschickter'], ['Curious', 'Neugieriger'], ['Cosy', 'Gemütlicher'], ['Noble', 'Edler'],
  ['Relaxed', 'Lässiger'], ['Smart', 'Schlauer'], ['Snappy', 'Flotter'], ['Sporty', 'Sportlicher'],
  ['Dreamy', 'Verträumter'], ['Alert', 'Wacher'], ['Tender', 'Zarter'], ['Golden', 'Goldener'],
  ['Silver', 'Silberner'], ['Blue', 'Blauer'], ['Red', 'Roter'], ['Green', 'Grüner'],
  ['Colourful', 'Bunter'], ['Yellow', 'Gelber'], ['Black', 'Schwarzer'], ['White', 'Weißer'],
  ['Brown', 'Brauner'], ['Grey', 'Grauer'], ['Little', 'Kleiner'], ['Big', 'Großer'],
  ['Strong', 'Starker'], ['Soft', 'Leiser'], ['Fine', 'Feiner'], ['Cool', 'Cooler'],
  ['Nice', 'Netter'], ['Witty', 'Witziger'], ['Honest', 'Ehrlicher'], ['Busy', 'Emsiger'],
  ['Lucky', 'Glücklicher'], ['Cheerful', 'Heiterer'], ['Plucky', 'Kecker'], ['Crafty', 'Listiger'],
  ['Mighty', 'Mächtiger'], ['Splendid', 'Prächtiger'], ['Swift', 'Rascher'], ['Able', 'Tüchtiger'],
  ['Merry', 'Vergnügter'], ['Content', 'Zufriedener'], ['Diligent', 'Fleißiger'], ['Fearless', 'Furchtloser'],
];

const ANIMALS = [
  ['Eagle', 'Adler'], ['Monkey', 'Affe'], ['Bear', 'Bär'], ['Beaver', 'Biber'],
  ['Buffalo', 'Büffel'], ['Badger', 'Dachs'], ['Dolphin', 'Delfin'], ['Moose', 'Elch'],
  ['Donkey', 'Esel'], ['Falcon', 'Falke'], ['Pheasant', 'Fasan'], ['Finch', 'Fink'],
  ['Fish', 'Fisch'], ['Frog', 'Frosch'], ['Fox', 'Fuchs'], ['Vulture', 'Geier'],
  ['Gecko', 'Gecko'], ['Shark', 'Hai'], ['Hamster', 'Hamster'], ['Hare', 'Hase'],
  ['Stag', 'Hirsch'], ['Lobster', 'Hummer'], ['Dog', 'Hund'], ['Hedgehog', 'Igel'],
  ['Polecat', 'Iltis'], ['Jaguar', 'Jaguar'], ['Cockatoo', 'Kakadu'], ['Tomcat', 'Kater'],
  ['Koala', 'Koala'], ['Hummingbird', 'Kolibri'], ['Crane', 'Kranich'], ['Crab', 'Krebs'],
  ['Cuckoo', 'Kuckuck'], ['Salmon', 'Lachs'], ['Leopard', 'Leopard'], ['Lion', 'Löwe'],
  ['Lynx', 'Luchs'], ['Marten', 'Marder'], ['Mole', 'Maulwurf'], ['Pug', 'Mops'],
  ['Otter', 'Otter'], ['Panda', 'Panda'], ['Parrot', 'Papagei'], ['Pelican', 'Pelikan'],
  ['Peacock', 'Pfau'], ['Penguin', 'Pinguin'], ['Puma', 'Puma'], ['Raven', 'Rabe'],
  ['Swan', 'Schwan'], ['Seal', 'Seehund'], ['Sparrow', 'Spatz'], ['Woodpecker', 'Specht'],
  ['Bull', 'Stier'], ['Stork', 'Storch'], ['Tiger', 'Tiger'], ['Toucan', 'Tukan'],
  ['Owl', 'Uhu'], ['Raccoon', 'Waschbär'], ['Whale', 'Wal'], ['Wolf', 'Wolf'],
  ['Wombat', 'Wombat'], ['Yak', 'Yak'], ['Gorilla', 'Gorilla'], ['Flamingo', 'Flamingo'],
];

/** "3F9A 11C2 7B04 E8D1" → "Brave Fox" (first 12 bits: 6 for the adjective, 6 for the animal). */
export function friendlyName(fingerprint) {
  const bits = parseInt(String(fingerprint).replace(/\s/g, '').slice(0, 3), 16);
  if (Number.isNaN(bits)) return '';
  const i = lang === 'de' ? 1 : 0;
  return `${ADJECTIVES[bits >> 6][i]} ${ANIMALS[bits & 63][i]}`;
}
