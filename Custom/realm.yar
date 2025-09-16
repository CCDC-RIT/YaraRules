rule Realm{
    meta:
        author: "Braeden Villano"
        creation_date = "2025-03-20"
        last_modified = "2025-03-20"
        threat_name = "Realm"
        severity = 100
        os = "multi"
    strings:
        $a= "eldritch"
        $b = "tavern" 
        $c = "TasktomeTomeimixSlimMasknote"
        $d = "stepWithDwarf"
        $e = "tome"
        $f = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/ossl-modules"
        $g = "get_payload"
        $h = "/home/runner/work/_temp/realm_build/x86_64-unknown-linux-musl/release/build/openssl-sys-b82835967498cb0e/out/openssl-build/install/lib/engines-3"
        $i = "imix"
        $j = "unknown control command"
        $k = "cmd=%s, value=%s"
        $l = "cmd=%s, value=%s"
        $m = "Registered ID:"
        $n = "IP Address:%s"
        $crate_id = "index.crates.io-6f17d22bba15001f"
        $imix_warning = "The original imix binary will still exist so you may wish to delete"
    condition:
        any of them
}