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
        $a1  = "/etc/system-id"             
        $a2  = "main.eldritch"                 
        $a3  = "claim_tasks"                     
        $a4  = "report_task_output"  
        $a5  = "tavern"
        $a6  = "eldritch"
        $a7 = "tome"
        $a8 = "get_payload"
        $a9 = "imix"
        $a10 = "unknown control command"
        $a11 = "cmd=%s"
        $a12 = "cmd=%s, value=%s"
        $a13 = "Registered ID:"
        $a14 = "IP Address:%s"
        $a15 = "stepWithDwarf"
        $b1 = "TasktomeTomeimixSlimMasknote"
        $b2 = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/ossl-modules"
        $b3 = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/engines-3"
        $b4 = "index.crates.io-6f17d22bba15001f"
        $b5 = "The original imix binary will still exist so you may wish to delete"
    condition:
        ($elf_magic at 0 and 8 of ($a*)) or any of ($b*)
}
