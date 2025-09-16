rule CCDC_Linux_Realm {
    meta:
        author = "lehadarat"
        creation_date = "2025-09-15"
        last_modified = "2025-09-15"
        arch_context = "x86,x86_64"
        scan_context = "file, memory"
        os = "linux"
    strings:
        $elf_magic = { 7F 45 4C 46 }                                     /* ELF header */
        $a  = { 49 4D 49 58 5F 53 45 52 56 45 52 5F 50 55 42 4B 45 59 }   /* "IMIX_SERVER_PUBKEY" */
        $b  = { 49 4D 49 58 5F 48 4F 53 54 5F 49 44 }                     /* "IMIX_HOST_ID" */
        $c  = { 2F 65 74 63 2F 73 79 73 74 65 6D 2D 69 64 }               /* "/etc/system-id" */
        $d  = { 6D 61 69 6E 2E 65 6C 64 72 69 74 63 68 }                  /* "main.eldritch" */
        $e  = { 49 4D 49 58 5F 43 41 4C 4C 42 41 43 4B 5F 55 52 49 }      /* "IMIX_CALLBACK_URI" */
        $f  = { 49 4D 49 58 5F 52 55 4E 5F 4F 4E 43 45 }                  /* "IMIX_RUN_ONCE" */
        $g  = { 63 6C 61 69 6D 5F 74 61 73 6B 73 }                        /* "claim_tasks" */
        $h  = { 72 65 70 6F 72 74 5F 74 61 73 6B 5F 6F 75 74 70 75 74 }  /* "report_task_output" */
        $i  = { 65 6C 64 72 69 74 63 68 }                                /* "eldritch" */
        $j  = { 74 61 76 65 72 6E }                                       /* "tavern" */

    condition:
        $elf_magic at 0 and 3 of ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j)
}
