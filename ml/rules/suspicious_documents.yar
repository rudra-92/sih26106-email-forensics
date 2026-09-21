/*
   suspicious_documents.yar - YARA rules for suspicious macro patterns and embedded triggers
*/

rule Office_AutoExec_Macro
{
    meta:
        description = "Detects Office auto-execution macro procedures"
        category = "forensic_indicator"
        severity = "high"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Auto_Open" nocase
        $a4 = "Workbook_Open" nocase
        $a5 = "AutoExec" nocase
        $wscript = "WScript.Shell" nocase
        $shell = "Shell.Application" nocase
    condition:
        any of ($a*) and ($wscript or $shell)
}

rule Suspicious_PDF_Action
{
    meta:
        description = "Detects PDF active content triggers"
        category = "forensic_indicator"
        severity = "medium"
    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript"
        $js2 = "/JS"
        $openaction = "/OpenAction"
        $launch = "/Launch"
        $embed = "/EmbeddedFile"
    condition:
        $pdf at 0 and (2 of ($js*, $openaction, $launch, $embed))
}
