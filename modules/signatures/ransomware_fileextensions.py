﻿from lib.cuckoo.common.abstracts import Signature

class RansomwareExtensions(Signature):
    name = "ransomware_extensions"
    description = "Appends known ransomware file extensions to files that have been encrypted"
    severity = 3
    families = []
    categories = ["ransomware"]
    authors = ["Kevin Ross", "bartblaze"]
    minimum = "1.2"
    ttp = ["T1486"]

    indicators = {
        r".*\.toxcrypt$": "ToxCrypt",
        r".*\.hydracrypt_ID_[a-z0-9]{8}$": "HydraCrypt",
        r".*\.hydracrypttmp_ID_[a-z0-9]{8}$": "HydraCrypt",
        #r".*\.locked$": "Locked",  # duplicate
        r".*\.cerber$": "Cerber",
        r".*\.cerber2$": "Cerber",
        r".*\.cerber3$": "Cerber",
        r".*\.encrypt$": "multi-family",
        r".*\.R5A$": "7ev3n",
        r".*\.R4A$": "7ev3n",
        r".*\.herbst$": "Herbst",
        r".*\.CrySiS$": "Crysis",
        r".*\.bart\.zip$": "Bart",
        r".*\.crypt$": "CryptXXX",
        r".*\.crypz$": "CryptXXX",
        r".*\.cryp1$": "CryptXXX",
        r".*\.[0-9A-F]{32}\.[0-9A-F]{5}$": "CryptXXX",
        r".*\.id_[^\/]*\.scl$": "CryptFile2",
        r".*\.id_[^\/]*\.rscl$": "CryptFile2",
        r".*\.razy$": "Razy",
        r".*\.Venus(f|p)$": "VenusLocker",
        r".*\.fs0ciety$": "Fsociety",
        r".*\.cry$": "CryLocker",
        r".*\.locklock$": "LockLock",
        r".*\.fantom$": "Fantom",
        r".*_nullbyte$": "Nullbyte",
        r".*\.purge$": "Globe",
        r".*\.globe$": "Globe",
        r".*\.raid10$": "Globe",
        r".*\.lovewindows$": "Globe",
        r".*\.domino$": "Domino",
        r".*\.wflx$": "WildFire-Locker",
        r".*\.locky$": "Locky",
        r".*\.zepto$": "Locky",
        r".*\.odin$": "Locky",
        r".*\.shit$": "Locky",
        r".*\.thor$": "Locky",
        r".*\.aesir$": "Locky",
        r".*\.zzzzz$": "Locky",
        r".*\.osiris$": "Locky",
        r".*\.locked$": "multi-family",
        r".*\.encrypted$": "multi-family",
        r".*dxxd$": "DXXD",
        r".*\.~HL[A-Z0-9]{5}$": "HadesLocker",
        r".*\.exotic$": "Exotic",
        r".*\.k0stya$": "Kostya",
        r".*\.1txt$": "Enigma",
        r".*\.0x5bm$": "Nuke",
        r".*\.nuclear55$": "Nuke",
        r".*\.comrade$": "Comrade-Circle",
        r".*\.rip$": "KillerLocker",
        r".*\.adk$": "AngryDuck",
        r".*\.lock93$": "Lock93",
        r".*\.Alcatraz$": "Alcatraz-Locker",
        r".*\.dCrypt$": "DummyLocker",
        #r".*\.enc$": "encryptJJS",
        r".*\.rnsmwr$": "Gremit",
        r".*\.da_vinci_code$": "Troldesh",
        r".*\.magic_software_syndicate$": "Troldesh",
        r".*\.no_more_ransom$": "Troldesh",
        r".*_luck$": "CryptoLuck",
        r".*\.CHIP$": "CHIP",
        r".*\.KRAB$": "GandCrab",
        r".*\.DALE$": "CHIP",
        r".*\.sexy$": "PayDay",
        r".*\.kraken$": "Kraken",
        r".*\.lesli$": "CryptoMix",
        r".*\.sage$": "Sage",
        r".*\.CRYPTOSHIELD$": "CryptoShield",
        r".*\.serpent$": "Serpent",
        r".*\.REVENGE$": "Revenge",
        r".*\.RYK$": "Ryuk",
        r".*\.FTCODE$": "FTCode",
        r".*\.Lazarus$": "Ouroboros",
        r".*\.Lazarus+$": "Ouroboros",
        r".*\.KRONOS$": "Ouroboros",
        r".*\.Yatron$": "Yatron",
        r".*\.HCY$": "HildaCrypt",
        r".*\.guarded$": "GarrantyDecrypt",
        r".*\.lilocked$": "Lilocked",
        r".*\.ragnarok_cry$": "Ragnarok",
        r".*\.ragnarok$": "Ragnarok",
        r".*\.ragnar_[A-Z0-9]{8}$": "RagnarLocker",
        r".*\.key$": "PwndLocker",
        r".*\.pwnd$": "PwndLocker",
        r".*\.pr[o0]L[o0]ck$": "ProLock",
        r".*\.abcd$": "LockBit",
        r".*\.lockbit$": "LockBit",
        r".*\.corona-lock": "CovidRansomware",
        r".*\.thanos$": "Tycoon",
        r".*\.grinch$": "Tycoon",
        r".*\.redrum$": "Tycoon",
        r".*\.*wasted$": "WastedLocker",
        r".*\.CONTI$": "Conti",
        r".*\.vhd$": "VHD",
        r".*\.ragn@r_[A-Z0-9]{8}$": "RagnarLocker",
        r".*\.WannaCash$": "WannaCash",
        r".*\.avdn$": "Avaddon",
        # Appends additional email and/or extension after .mailto
        r".*\.mailto": "Netwalker-Mailto",
        r".*\.GNNCRY$": "GonnaCry",
        r".*\.XONIF$": "Fonix",
        r".*\.pandemic$": "Pandemic",
        r".*\.ROGER$": "ROGER",
    }

    def run(self):
        for pattern, family in self.indicators.items():
            results = self.check_write_file(pattern, regex=True, all=True)
            if results and len(results) > 15:
                if families:
                    self.families = [family]
                    self.description = ("Appends a known %s ransomware file extension to files that have been encrypted" % "/".join(self.families))
                return True

        return False
