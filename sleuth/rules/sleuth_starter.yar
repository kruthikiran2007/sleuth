/* Starter YARA ruleset for Sleuth (defensive static analysis only).

These are generic string-signature rules — markers commonly found in packed,
dual-use, or malicious tooling. They describe indicators, not code; nothing
here executes, delivers, or weaponizes anything. Triage aids only.
*/

rule upx_packer
{
    meta:
        severity = "medium"
        description = "Binary packed with UPX (magic marker present)"
    strings:
        $upx_magic = "UPX!" fullword
        $upx_sec0  = "UPX0" fullword
        $upx_sec1  = "UPX1" fullword
    condition:
        any of them
}

rule reverse_shell_patterns
{
    meta:
        severity = "high"
        description = "Reverse-shell style string combo (interactive shell + socket + connect)"
    strings:
        $bin_sh    = "/bin/sh" fullword
        $socket    = "socket" fullword
        $connect   = "connect" fullword
        $cmd_exe   = "cmd.exe" fullword
        $cmd_flag  = "/c" fullword
    condition:
        (all of ($bin_sh, $socket, $connect)) or ($cmd_exe and $cmd_flag)
}

rule credential_harvesting_keywords
{
    meta:
        severity = "high"
        description = "Credential-harvesting / keylogging string markers"
    strings:
        $keylog        = "keylog" fullword
        $getasync      = "GetAsyncKeyState" fullword
        $sekurlsa      = "sekurlsa" fullword
        $mimikatz      = "mimikatz" fullword
        $password_dump = "password dump" fullword
    condition:
        any of them
}

rule suspicious_powershell
{
    meta:
        severity = "medium"
        description = "Suspicious obfuscated PowerShell invocation markers"
    strings:
        $encoded   = "-EncodedCommand" fullword
        $iex_paren = "IEX(" fullword
        $invoke    = "Invoke-Expression" fullword
        $frombase64 = "FromBase64String" fullword
    condition:
        any of them
}

rule hacktool_strings
{
    meta:
        severity = "medium"
        description = "Known hacktool string markers (credential dumping / remote exec)"
    strings:
        $pwdump = "pwdump" fullword
        $psexec = "psexec" fullword
        $sekdump = "secretsdump" fullword
        $psrem   = "Enter-PSSession" fullword
    condition:
        any of them
}

rule ransomware_keywords
{
    meta:
        severity = "high"
        description = "Ransomware-style ransom note / payment demand markers"
    strings:
        $note        = "YOUR FILES HAVE BEEN ENCRYPTED" fullword
        $onion       = ".onion" fullword
        $bitcoin     = "bitcoin" fullword
        $decrypt_key = "decryption key" fullword
    condition:
        $note or $decrypt_key or ($onion and $bitcoin)
}
