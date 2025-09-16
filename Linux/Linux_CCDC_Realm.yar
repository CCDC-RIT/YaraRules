rule Realm{
    meta: 
        author = "RIT CCDC Team"
        creation_date = "2025-09-15"
        last_modified = "2025-09-15"
        arch_context = "x86,x86_64"
        scan_context = "file, memory"
        threat_name = "Realm"
        severity = 100
        os = "linux"
    strings:
        $elf_magic = { 7F 45 4C 46 }                                     /* ELF header */
        $a1  = { 49 4D 49 58 5F 53 45 52 56 45 52 5F 50 55 42 4B 45 59 }   /* "IMIX_SERVER_PUBKEY" */
        $a2  = { 49 4D 49 58 5F 48 4F 53 54 5F 49 44 }                     /* "IMIX_HOST_ID" */
        $a3  = { 2F 65 74 63 2F 73 79 73 74 65 6D 2D 69 64 }               /* "/etc/system-id" */
        $a4  = { 6D 61 69 6E 2E 65 6C 64 72 69 74 63 68 }                  /* "main.eldritch" */
        $a5  = { 49 4D 49 58 5F 43 41 4C 4C 42 41 43 4B 5F 55 52 49 }      /* "IMIX_CALLBACK_URI" */
        $a6  = { 49 4D 49 58 5F 52 55 4E 5F 4F 4E 43 45 }                  /* "IMIX_RUN_ONCE" */
        $a7  = { 63 6C 61 69 6D 5F 74 61 73 6B 73 }                        /* "claim_tasks" */
        $a8  = { 72 65 70 6F 72 74 5F 74 61 73 6B 5F 6F 75 74 70 75 74 }  /* "report_task_output" */
        $a9  = "tavern"
        $a10  = "eldritch"
        $a11 = "tome"
        $a12 = "get_payload"
        $a13 = "imix"
        $a14 = "unknown control command"
        $a15 = "cmd=%s"
        $a16 = "cmd=%s, value=%s"
        $a17 = "Registered ID:"
        $a18 = "IP Address:%s"
        $b1 = "stepWithDwarf"
        $b2 = "TasktomeTomeimixSlimMasknote"
        $b3 = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/ossl-modules"
        $b4 = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/engines-3"
        $b5 = "index.crates.io-6f17d22bba15001f"
        $b6 = "The original imix binary will still exist so you may wish to delete"
    condition:
        ($elf_magic at 0 and 4 of ($a*)) or any of ($b*)
}