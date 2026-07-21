/* rules/suspicious.yar - Starter YARA ruleset for APK Sentinel.
   Add more rules here or point config.json's yara.rules_dir at a bigger
   collection (e.g. a clone of a public Androguard/Koodous rule pack). */

rule Dynamic_Code_Loading
{
    meta:
        description = "Uses DexClassLoader or reflection-based dynamic loading"
        severity = "medium"
    strings:
        $a = "DexClassLoader" ascii
        $b = "loadClass" ascii
        $c = "dalvik.system.PathClassLoader" ascii
    condition:
        any of them
}

rule Root_Detection_Or_Abuse
{
    meta:
        description = "References to su/root/magisk binaries"
        severity = "medium"
    strings:
        $su = "/system/bin/su" ascii
        $su2 = "/system/xbin/su" ascii
        $magisk = "magisk" ascii nocase
        $busybox = "busybox" ascii nocase
    condition:
        any of them
}

rule Shell_Command_Execution
{
    meta:
        description = "Runtime.exec / ProcessBuilder shell execution"
        severity = "high"
    strings:
        $a = "Runtime.getRuntime().exec" ascii
        $b = "ProcessBuilder" ascii
        $c = "/system/bin/sh" ascii
    condition:
        any of them
}

rule Accessibility_Overlay_Abuse
{
    meta:
        description = "Accessibility service combined with overlay window abuse (banking trojan pattern)"
        severity = "high"
    strings:
        $acc = "AccessibilityService" ascii
        $overlay = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay2 = "SYSTEM_ALERT_WINDOW" ascii
    condition:
        $acc and (any of ($overlay*))
}

rule SMS_Interception
{
    meta:
        description = "SMS receiver combined with network capability (OTP theft pattern)"
        severity = "high"
    strings:
        $recv = "SMS_RECEIVED" ascii
        $abort = "abortBroadcast" ascii
    condition:
        all of them
}

rule Packed_Or_Obfuscated_Strings
{
    meta:
        description = "Common commercial packer/obfuscator markers"
        severity = "low"
    strings:
        $a = "com.tencent.StubShell" ascii
        $b = "com.qihoo.util" ascii
        $c = "ijiami" ascii nocase
        $d = "bangcle" ascii nocase
    condition:
        any of them
}
