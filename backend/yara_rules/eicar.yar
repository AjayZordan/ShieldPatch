rule EICAR_Test
{
    meta:
        author = "ajay"
        description = "Detect EICAR test file"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e
}
