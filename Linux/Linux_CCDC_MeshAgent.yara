rule MeshAgentElf
{
	meta:
		author = "Oleksandr Maniukhin"
        organization = "CCDC RIT"
		description = "Core strings for MeshAgent"
        threat_name = "MeshAgent"
        os = "Linux"
        created = "2025-09-16"
        last_modified = "2025-09-18"

    // strings for .lf file
    strings:
        $elf_magic = { 7F 45 4C 46 }

        $a1  = /require\(['"]MeshAgent['"]\)/ ascii
        $a2  = "wss://swarm.meshcentral.com:443/agent.ashx"
        $a3  = "wss://meshcentral.com:443/agent.ashx"
        $a4  = "MeshAgent_AgentMode_IPAddressChanged_Handler(%d)"
        $a5  = "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Pong Received"
        $a6  = "AgentCore/MeshServer_ControlChannel_IdleTimeout(): Sending Ping"
        $a7  = "AgentCore/MeshServer_ControlChannel_IdleTimeout(): PONG TIMEOUT"
        $a8  = "meshServiceName"
        $a9  = "MeshCentral"
        $a10 = "AgentCapabilities"
        $a11 = "Mesh agent started."
        $a12 = "/var/run/meshagent.pid"
        $a13 = ".meshagent.pid"
        $a14 = "_RemoteDesktopUID"
        $a15 = "_RemoteDesktopStream"
        $a16 = "_RemoteDesktopPTRS"
        $a17 = "_MeshAgent_DataPing_Timeout"
        $a18 = "GenerateAgentCertificate"
        $a19 = "_MeshAgent_DataPingArray"
        $a20 = "meshagent"
        $a21 = "[\"--meshServiceName=\\\"%s\\\"\"]"
        $a22 = "MeshAgentPtr"
        $a23 = "meshcore/agentcore.c"
        $a24 = "_MeshDesktop_AgentPtr"
        $a25 = "MeshDesktop"
        $a26 = "getRemoteDesktopStream"
        $a27 = "RemoteMouseMove: (%d, %d)"
        $a28 = "http.Agent"
   
    condition:
        $elf_magic and 10 of ($a*)
    
}

rule MeshAgentMSH
{
	meta:
		author = "Oleksandr Maniukhin"
        organization = "CCDC RIT"
		description = "Core strings for MeshAgent"
        threat_name = "MeshAgent"
        os = "Linux"
        created = "2025-09-16"
        last_modified = "2025-09-18"

    // strings for .msh file
    strings:
        $b1  = "MeshName=TacticalRMM"
        $b2  = "MeshType=2"
        $b3  = "MeshServer=wss://mesh."

        // Regex for IDs (flexible, matches any hex of sufficient length)
        $a_meshid   = /MeshID=0x[0-9A-F]{64,}/
        $a_serverid = /ServerID=[0-9A-F]{64,}/

    condition:
        2 of them
}
