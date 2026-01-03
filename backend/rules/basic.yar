rule Suspicious_PE_File
{
    meta:
        description = "Detects suspicious Windows PE executables"
        author = "ShieldWatch"

    strings:
        $mz = "MZ"

    condition:
        $mz at 0 and filesize < 5MB
}
