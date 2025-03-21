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
    condition:
        $a or $b
}