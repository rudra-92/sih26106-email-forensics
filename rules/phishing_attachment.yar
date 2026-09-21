/*
   phishing_attachment.yar - YARA rules for credential-harvesting HTML attachments
*/

rule Phishing_HTML_Form_Submission
{
    meta:
        description = "Detects HTML attachment containing credential harvesting form"
        category = "forensic_indicator"
        severity = "high"
    strings:
        $form = "<form" nocase
        $pass = "type=\"password\"" nocase
        $pass2 = "type='password'" nocase
        $sub = "method=\"post\"" nocase
        $sub2 = "method='post'" nocase
        $login1 = "sign in" nocase
        $login2 = "log in" nocase
        $login3 = "verify your account" nocase
    condition:
        $form and ($pass or $pass2) and ($sub or $sub2) and any of ($login*)
}

rule Phishing_Obfuscated_Script
{
    meta:
        description = "Detects heavily obfuscated JavaScript in attachment"
        category = "forensic_indicator"
        severity = "medium"
    strings:
        $s1 = "unescape(" nocase
        $s2 = "fromCharCode(" nocase
        $s3 = "document.write(" nocase
        $s4 = "eval(" nocase
    condition:
        3 of ($s1, $s2, $s3, $s4)
}
