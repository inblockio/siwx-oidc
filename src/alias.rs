//! Tier 1 of the identity model: a human-readable **alias**, deterministically
//! seeded from the DID.
//!
//! See the three-tier table in `CLAUDE.md`. The alias is the tier the USER
//! owns: Synapse's `displayname`, freely rewritable by its owner at any time
//! ([the ACL probe's leg 5][probe] measured a plain user's `PUT` to
//! `displayname` as **200** on the same image where their `PUT` to
//! `io.inblock.did` is **403**). This module only decides what a brand-new
//! account STARTS with.
//!
//! [probe]: ../../docs/audits/2026-09-10-msc4133-acl-probe.md
//!
//! # Why a generated name, and not the localpart
//!
//! The seed used to be the raw DID, which was a security defect: a
//! provider-asserted-looking identity sitting in a field its subject can
//! rewrite means a consumer reading displayname-as-identity can be handed
//! *someone else's* DID. That was fixed by seeding the localpart instead —
//! honest, but `@2wjyn3jhbh7savin` is not a name, and a room full of them is
//! unreadable.
//!
//! A pseudonym fixes the readability without re-opening the hole, because it
//! is **not an identifier and cannot be mistaken for one**: it carries no DID,
//! no key material, and nothing a relying party could parse. It is decoration
//! over an identity that lives in the other two tiers.
//!
//! # Collisions are expected, and are not a defect
//!
//! With `FIRST_NAMES.len() * SURNAMES.len()` combinations the birthday bound
//! puts the first expected collision in the low hundreds of accounts, and two
//! users sharing "Ingrid Moreau" is fine: Matrix clients disambiguate
//! duplicate display names within a room by showing the MXID, the MXID itself
//! is derived from 80 bits of hash ([`crate::mxid`]), and the attested DID is
//! published separately. Never treat this string as unique, never key anything
//! on it, and never compare it.
//!
//! # Canonicalisation is shared with the MXID, deliberately
//!
//! The seed runs through [`crate::mxid::canonicalize`], so a mixed-case
//! `did:pkh` and its lowercase twin — which are ONE Matrix account, because
//! EIP-55 case is a checksum — also get ONE alias. Deriving the alias from the
//! raw string instead would let the same person appear under two names
//! depending on how their wallet spelled the address that day. The same rule
//! preserves `did:key`/`did:peer` case, where case IS key material.
//!
//! # The lists may be extended; they must not be REORDERED
//!
//! An index is `digest mod len`, so appending names changes which alias a
//! given DID would get. That is safe in practice because the alias is written
//! ONCE, at first sign-in, and then belongs to the user — an extension changes
//! what future accounts are seeded with, never what an existing account shows.
//! Reordering or deleting entries has the same effect and no extra benefit, so
//! append only.

use sha2::{Digest, Sha256};

/// Domain separator. The MXID derivation hashes the bare canonical DID
/// ([`crate::mxid::localpart_for`]); without this prefix the alias would be a
/// second projection of the *same* digest, so the two would be correlated
/// derivations of one secretless input and could never be changed
/// independently. It also means a future tier-1 scheme can bump `v1` and leave
/// every other derivation untouched.
const ALIAS_DOMAIN: &[u8] = b"siwx-oidc/alias/v1\x00";

/// Derive the display alias for a DID: `"Firstname Surname"`.
///
/// Deterministic, infallible, and pure. Two calls with the same DID always
/// agree; a `did:pkh` in any case spelling agrees with itself.
pub fn alias_for(did: &str) -> String {
    let canonical = crate::mxid::canonicalize(did);
    let mut hasher = Sha256::new();
    hasher.update(ALIAS_DOMAIN);
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();

    // Four bytes per index: with a 2^32 range over a ~250-entry list the
    // modulo bias is on the order of 1e-7, i.e. far below any effect a human
    // could observe in a name distribution. Distinct byte ranges for the two
    // words, so the surname is not a function of the given name.
    let first = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let last = u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]]);

    format!(
        "{} {}",
        FIRST_NAMES[first as usize % FIRST_NAMES.len()],
        SURNAMES[last as usize % SURNAMES.len()]
    )
}

/// Given names. ASCII only — the alias is copied, typed, searched and rendered
/// by clients of wildly varying quality, and a name nobody can type is a worse
/// pseudonym than a plain one.
const FIRST_NAMES: &[&str] = &[
    "Aaliyah", "Adam", "Adele", "Adrian", "Agnes", "Ahmad", "Aiko", "Alba", "Alden", "Alena",
    "Alessio", "Alice", "Amara", "Amir", "Anders", "Andrea", "Aneta", "Anika", "Anton", "Arden",
    "Ari", "Arlo", "Asha", "Astrid", "Aurora", "Axel", "Ayla", "Bastian", "Beatrix", "Bela",
    "Benno", "Bianca", "Birgit", "Bodhi", "Bram", "Brenna", "Bruno", "Caleb", "Camila", "Carsten",
    "Cato", "Cecile", "Celia", "Cesar", "Chiara", "Cillian", "Claes", "Clara", "Colm", "Cora",
    "Cyrus", "Dagny", "Dalia", "Damaris", "Daniil", "Dara", "Darius", "Delia", "Diego", "Dima",
    "Dinah", "Dorian", "Duarte", "Eamon", "Edda", "Eero", "Efrain", "Eider", "Elan", "Elif",
    "Elias", "Elke", "Elodie", "Eloise", "Elsa", "Emeka", "Emil", "Enzo", "Esben", "Esme", "Ewan",
    "Fabian", "Faye", "Felix", "Fenna", "Fiona", "Florian", "Frida", "Gabor", "Gaia", "Galen",
    "Gemma", "Georgi", "Gerda", "Gideon", "Gita", "Greta", "Gunnar", "Hadi", "Hana", "Hannes",
    "Harriet", "Hedda", "Helena", "Henrik", "Hilde", "Hiroshi", "Ida", "Idris", "Ilan", "Ilse",
    "Imre", "Inaya", "Ines", "Ingrid", "Iona", "Iris", "Isolde", "Ivar", "Jaana", "Jacinta",
    "Jalil", "Janek", "Jarek", "Jasmin", "Javier", "Jens", "Jesper", "Joana", "Johan", "Jonas",
    "Jorn", "Josefa", "Juno", "Kaia", "Kamil", "Karima", "Karl", "Kasper", "Katja", "Keiko",
    "Kenji", "Kiran", "Klara", "Konrad", "Lars", "Laszlo", "Leander", "Leila", "Lena", "Leon",
    "Levin", "Liana", "Lilja", "Linnea", "Liv", "Lorcan", "Lotte", "Luca", "Lucia", "Ludvig",
    "Luka", "Mads", "Maeve", "Magnus", "Maja", "Manon", "Marek", "Mariam", "Marlow", "Marta",
    "Mateo", "Mathilde", "Matteo", "Maya", "Melina", "Mercer", "Mika", "Milan", "Mira", "Miro",
    "Mona", "Nadia", "Naomi", "Nasir", "Nela", "Neve", "Nikolai", "Nils", "Noor", "Nora", "Odin",
    "Ofelia", "Oksana", "Olen", "Olivia", "Omar", "Ondine", "Orla", "Oskar", "Otto", "Paavo",
    "Paloma", "Paola", "Pavel", "Pedro", "Petra", "Pia", "Piotr", "Quentin", "Rafael", "Raisa",
    "Ramona", "Rania", "Raven", "Reidar", "Rhona", "Rina", "Rocio", "Roman", "Rosa", "Rune",
    "Ruth", "Saga", "Salma", "Samira", "Sander", "Sanna", "Sasha", "Selma", "Senna", "Sergio",
    "Signe", "Silas", "Simone", "Sina", "Sofia", "Solveig", "Soren", "Stellan", "Sven", "Tadeo",
    "Talia", "Tamar", "Tariq", "Tessa", "Theo", "Thora", "Tibor", "Tilda", "Timo", "Tomas", "Tova",
    "Ulla", "Ulrik", "Uma", "Vera", "Vidar", "Viggo", "Vilma", "Vito", "Wren", "Xenia", "Yara",
    "Yasmin", "Yusuf", "Zaida", "Zane", "Zara", "Zeno", "Zora",
];

/// Surnames. Same ASCII rule as [`FIRST_NAMES`]. A handful of strings appear in
/// both lists (Elias, Hassan, Imani, Malik); the occasional "Elias Elias" is a
/// cosmetic curiosity, not a failure, and pruning them would only shrink the
/// space for nothing.
const SURNAMES: &[&str] = &[
    "Abadi",
    "Ackerman",
    "Adeyemi",
    "Aguilar",
    "Ahlberg",
    "Akiyama",
    "Albrecht",
    "Alvarez",
    "Andersen",
    "Antonov",
    "Aquino",
    "Arnaud",
    "Asante",
    "Ashworth",
    "Aubert",
    "Avila",
    "Bachmann",
    "Baird",
    "Balogh",
    "Barros",
    "Bauer",
    "Beaumont",
    "Becker",
    "Belanger",
    "Benitez",
    "Berger",
    "Bergman",
    "Bianchi",
    "Bisset",
    "Blum",
    "Boateng",
    "Bogdan",
    "Bonnet",
    "Borg",
    "Brandt",
    "Bravo",
    "Brennan",
    "Brodie",
    "Bruni",
    "Bukowski",
    "Caldas",
    "Calvo",
    "Campos",
    "Carvalho",
    "Castellan",
    "Chandra",
    "Chastain",
    "Cheung",
    "Chowdhury",
    "Clausen",
    "Coelho",
    "Conti",
    "Cortes",
    "Cruz",
    "Dagher",
    "Dalgaard",
    "Damico",
    "Danilov",
    "Darcy",
    "Daskal",
    "Delacroix",
    "Delgado",
    "Demir",
    "Devlin",
    "Diallo",
    "Dinescu",
    "Dohnal",
    "Dragan",
    "Dubois",
    "Dufour",
    "Dumont",
    "Duran",
    "Eberhardt",
    "Egeland",
    "Eichel",
    "Eklund",
    "Elbaz",
    "Elias",
    "Engel",
    "Erikson",
    "Escobar",
    "Esteban",
    "Fabre",
    "Falk",
    "Farah",
    "Feldman",
    "Fernandes",
    "Ferrari",
    "Fischer",
    "Flores",
    "Fontaine",
    "Forsberg",
    "Frank",
    "Fujita",
    "Gagne",
    "Gallego",
    "Garrido",
    "Gaspar",
    "Gauthier",
    "Gerber",
    "Ghosh",
    "Gilani",
    "Gislason",
    "Glover",
    "Gomes",
    "Gorski",
    "Grimaldi",
    "Gruber",
    "Guerrero",
    "Gunnarsson",
    "Gupta",
    "Haas",
    "Hagen",
    "Halvorsen",
    "Hamdi",
    "Hanson",
    "Harding",
    "Hartmann",
    "Hassan",
    "Havel",
    "Hayashi",
    "Heinonen",
    "Herrera",
    "Hidalgo",
    "Hoffmann",
    "Holloway",
    "Holm",
    "Horvath",
    "Hoxha",
    "Hughes",
    "Ibarra",
    "Ilic",
    "Imani",
    "Ionescu",
    "Ivanov",
    "Iversen",
    "Jaeger",
    "Jansen",
    "Jaramillo",
    "Jelinek",
    "Jensen",
    "Jimenez",
    "Jokinen",
    "Jordan",
    "Kaiser",
    "Kallio",
    "Kamara",
    "Kaminski",
    "Kapoor",
    "Karlsen",
    "Kato",
    "Keita",
    "Kellerman",
    "Khouri",
    "Kimura",
    "Kingsley",
    "Kirsch",
    "Klein",
    "Kobayashi",
    "Kovac",
    "Kowalczyk",
    "Krause",
    "Kruger",
    "Kumar",
    "Kuznetsov",
    "Lagos",
    "Lambert",
    "Landry",
    "Larsen",
    "Laurent",
    "Leclerc",
    "Lehmann",
    "Lemos",
    "Leroy",
    "Lindqvist",
    "Lombardi",
    "Lopez",
    "Lorenz",
    "Lukic",
    "Lund",
    "Maalouf",
    "Madsen",
    "Maguire",
    "Mahmoud",
    "Maier",
    "Malik",
    "Mancini",
    "Mandel",
    "Marchetti",
    "Marino",
    "Markov",
    "Martel",
    "Matos",
    "Mbeki",
    "Meier",
    "Mendes",
    "Mercier",
    "Meyer",
    "Miller",
    "Mitra",
    "Mohr",
    "Molina",
    "Montes",
    "Moreau",
    "Moretti",
    "Mueller",
    "Nagy",
    "Nakamura",
    "Navarro",
    "Nesbitt",
    "Neumann",
    "Nguyen",
    "Nielsen",
    "Nikolic",
    "Norberg",
    "Nowak",
    "Nunez",
    "Obrien",
    "Okafor",
    "Oliveira",
    "Olsen",
    "Ortega",
    "Osei",
    "Ostrowski",
    "Padilla",
    "Palmer",
    "Papadakis",
    "Pardo",
    "Pavlov",
    "Pedersen",
    "Pereira",
    "Petrov",
    "Pham",
    "Pires",
    "Popescu",
    "Prakash",
    "Quintero",
    "Rahman",
    "Ramirez",
    "Rasmussen",
    "Reinhart",
    "Renard",
    "Reyes",
    "Ribeiro",
    "Richter",
    "Rinaldi",
    "Rivas",
    "Rosales",
    "Rossi",
    "Roux",
    "Rudolph",
    "Ruiz",
    "Sadiq",
    "Sandberg",
    "Santoro",
    "Sarkar",
    "Sauer",
    "Savic",
    "Schmidt",
    "Schneider",
    "Seifert",
    "Serrano",
    "Shah",
    "Shirazi",
    "Silva",
    "Simonsen",
    "Sinclair",
    "Skov",
    "Solberg",
    "Soriano",
    "Sousa",
    "Stefanov",
    "Stenger",
    "Suzuki",
    "Svensson",
    "Takahashi",
    "Tamm",
    "Tanaka",
    "Tavares",
    "Teixeira",
    "Thorne",
    "Tikhonov",
    "Toledo",
    "Torres",
    "Traore",
    "Ueda",
    "Ulrich",
    "Vargas",
    "Vasquez",
    "Vega",
    "Velasco",
    "Verhoeven",
    "Vidal",
    "Vogel",
    "Volkov",
    "Wagner",
    "Walsh",
    "Weber",
    "Wexler",
    "Whitaker",
    "Winter",
    "Yamada",
    "Yilmaz",
    "Zaher",
    "Zamora",
    "Zielinski",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The same DIDs the MXID vectors use, so the two derivations can be
    /// compared side by side when either changes.
    const PKH_LOWER: &str = "did:pkh:eip155:1:0x7a760ea15d76f935c8646b449af488c2b0021734";
    const PKH_MIXED: &str = "did:pkh:eip155:1:0x7A760ea15d76F935c8646b449AF488c2B0021734";
    const KEY_UPPER: &str = "did:key:z6MkmWziJJ2k3ckqVqnmMGVKefMhDSe4ZxrfvqksxDMGBa4v";
    const KEY_LOWER: &str = "did:key:z6mkmwzijj2k3ckqvqnmmgvkefmhdse4zxrfvqksxdmgba4v";

    /// Exact vectors, computed and verified against this implementation on
    /// 2026-09-11. Do NOT "fix" these to match a refactor: every account
    /// provisioned from here on is seeded with the value this function
    /// returns, so a change silently gives new users different names from the
    /// ones any documentation, screenshot or support ticket recorded.
    /// Appending to the lists changes these too — which is exactly why the
    /// alias is written once and then owned by the user (module doc).
    #[test]
    fn vectors_are_pinned() {
        assert_eq!(alias_for(PKH_LOWER), "Ayla Tikhonov");
        assert_eq!(alias_for(PKH_MIXED), "Ayla Tikhonov");
        assert_eq!(alias_for(KEY_UPPER), "Dagny Bianchi");
        assert_eq!(alias_for(KEY_LOWER), "Magnus Egeland");
    }

    #[test]
    fn deterministic_across_repeated_calls() {
        assert_eq!(alias_for(PKH_LOWER), alias_for(PKH_LOWER));
        assert_eq!(alias_for(KEY_UPPER), alias_for(KEY_UPPER));
    }

    /// The invariant that makes the alias safe to share with the MXID's
    /// canonicalisation: one account, one name. EIP-55 case is a checksum, so
    /// a wallet that spells its address differently must not rename the user.
    #[test]
    fn pkh_case_folding_gives_one_alias() {
        assert_eq!(
            alias_for(PKH_LOWER),
            alias_for(PKH_MIXED),
            "mixed-case and lowercase did:pkh are ONE account and must be ONE alias"
        );
    }

    /// The other half of the method-aware rule: `did:key` case IS key
    /// material, so two spellings are two different keys and must not collapse
    /// into one identity — see siwx-oidc#17.
    #[test]
    fn key_case_is_preserved_not_folded() {
        assert_ne!(
            alias_for(KEY_UPPER),
            alias_for(KEY_LOWER),
            "folding did:key case would map two different public keys to one alias"
        );
    }

    /// Shape: exactly two ASCII words, each capitalised. Asserted because the
    /// alias is written into someone else's Matrix profile, and a stray empty
    /// string there would make Synapse's `profiles` row and Element's
    /// fallback rendering disagree.
    #[test]
    fn shape_is_two_capitalised_ascii_words() {
        for did in [
            PKH_LOWER,
            KEY_UPPER,
            KEY_LOWER,
            "did:peer:0zQmZ",
            "did:example:xyz",
        ] {
            let alias = alias_for(did);
            let parts: Vec<&str> = alias.split(' ').collect();
            assert_eq!(parts.len(), 2, "alias must be exactly two words: {alias:?}");
            for part in parts {
                assert!(!part.is_empty(), "no empty word in {alias:?}");
                assert!(
                    part.chars().all(|c| c.is_ascii_alphabetic()),
                    "ASCII letters only, got {alias:?}"
                );
                assert!(
                    part.chars().next().unwrap().is_ascii_uppercase(),
                    "each word is capitalised: {alias:?}"
                );
            }
        }
    }

    /// The security property this tier exists for: whatever else changes, a
    /// DID must never reach the user-writable field. Checked case-insensitively
    /// because a lowercased DID is still a DID.
    #[test]
    fn an_alias_never_contains_a_did() {
        for did in [PKH_LOWER, PKH_MIXED, KEY_UPPER, KEY_LOWER] {
            let alias = alias_for(did).to_ascii_lowercase();
            assert!(!alias.contains("did:"), "alias leaked a DID: {alias}");
            assert!(!alias.contains("0x"), "alias leaked an address: {alias}");
        }
    }

    /// Both 4-byte windows are really used. A regression that indexed both
    /// words off the same bytes would still pass every test above while
    /// producing far fewer distinct names than the lists allow.
    #[test]
    fn both_words_vary_independently() {
        let mut firsts = HashSet::new();
        let mut lasts = HashSet::new();
        for i in 0..2000u32 {
            let alias = alias_for(&format!("did:key:z6Mktest{i}"));
            let (f, l) = alias.split_once(' ').unwrap();
            firsts.insert(f.to_string());
            lasts.insert(l.to_string());
        }
        assert!(
            firsts.len() > FIRST_NAMES.len() * 3 / 4,
            "given names barely varied: {} of {}",
            firsts.len(),
            FIRST_NAMES.len()
        );
        assert!(
            lasts.len() > SURNAMES.len() * 3 / 4,
            "surnames barely varied: {} of {}",
            lasts.len(),
            SURNAMES.len()
        );
    }

    /// Sanity on the space itself: enough combinations that a small community
    /// mostly sees distinct names. This is a floor, not a uniqueness claim —
    /// see the module doc on why collisions are acceptable.
    #[test]
    fn the_name_space_is_large_enough_to_be_worth_it() {
        assert!(
            FIRST_NAMES.len() * SURNAMES.len() > 50_000,
            "only {} combinations",
            FIRST_NAMES.len() * SURNAMES.len()
        );
        assert!(FIRST_NAMES.iter().all(|n| !n.is_empty()));
        assert!(SURNAMES.iter().all(|n| !n.is_empty()));
    }
}
