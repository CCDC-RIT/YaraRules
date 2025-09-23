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
        $elf_magic = { 7F 45 4C 46 }      /* ELF header */
        /* Category A strings: These are found in Realm implants but are shorter/not as unique as others so we look for 
                               multiple together to reduce false positives */
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
        /* Category B strings: These are longer, unique strings found in Realm implants  */
        $b1 = "TasktomeTomeimixSlimMasknote"
        $b2 = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/ossl-modules"
        $b3 = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/engines-3"
        $b4 = "The original imix binary will still exist so you may wish to delete"
        $b5 = "IMIX_SERVER_PUBKEY"
        $b6 = "IMIX_CALLBACK_URI"
        $b7 = "IMIX_CALLBACK_INTERVAL"
        $b8 = "IMIX_RETRY_INTERVAL"
        $b9 = "IMIX_PROXY_URI"
        $b10 = "IMIX_HOST_ID"
        $b11 = "IMIX_RUN_ONCE"
        $b12 = "IMIX_BEACON_ID"
        $b13 = "IMIX_LOG"
    condition:
        ($elf_magic at 0 and 5 of ($a*)) or (10 of ($a*)) or (any of ($b*)) 
        /* We want to trigger if we find at least 5 category A strings in an ELF file, or 10 category A strings (higher threshold to avoid potential false positives)
           Also triggers if any of the more unique Category B strings are found  */
}