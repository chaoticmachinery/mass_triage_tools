rule chopper_generic {
        meta:
                description = "Generic chopper shell detects"
                author = "Keven Murphy"
                reference = "not set"
                date = "2020/02/19"
        strings:
                $s0 = "eval" nocase
                $s1 = "base64" nocase
                $s2 = "unsafe" nocase
                $s4 = "passthru" nocase
                $s5 = "assert" nocase
                $s6 = "gzdeflate" nocase
                $s7 = "rot13" nocase
                $s8 = "/bin/sh" 
                $s9 = "/bin/bash"
                $s10 = "Shell" nocase
                $s11 = "Command" nocase
                $s12 = "include" nocase
                $s13 = "cmd" nocase
                $s14 = "/c" nocase
        condition:
                3 of ($s*) 
}

rule chopper_generic_aspx {
        meta:
                description = "Generic aspx chopper shell detects"
                author = "Keven Murphy"
                reference = "not set"
                date = "2020/02/19"
        strings:
                $s0 = "eval" nocase
                $s1 = "Page Language=\"Jscript\"" nocase
                $s2 = ",\"unsafe\"" nocase
                $s3 = "Request.Item[\"" nocase
                $s4 = "WebServices.InitalizeWebServices" nocase
                $s5 = "Jscript" nocase
                $s6 = "WebHandler Language=\"C#\"" nocase
                $s7 = "execute" nocase
                $s8 = "GetEncoding(" nocase
                $s9 = "Base64" nocase
        condition:
                3 of ($s*)
}

rule chopper_generic_aspx2 {
        meta:
                description = "Generic iis chopper shell detects"
                author = "Keven Murphy"
                reference = "https://publicintelligence.net/fbi-defense-contractor-intrusions/"
                date = "2020/02/19"
        strings:
                $s1 = "JScript" nocase
                $s2 = "runat=\"\"server\"\"" nocase
                $s3 = "runat=\"server\"" nocase      
                $s4 = "Page_Load()" nocase
                $s5 = "eval(" nocase
                $s6 = "unsafe" nocase
                $s7 = "System.Convert.FromBase64String" nocase
                $s8 = "Request.Item[" nocase
                
        condition:
                2 of ($s*)

}

rule chopper_generic_iis {
        meta:
                description = "Generic iis chopper shell detects"
                author = "Keven Murphy"
                reference = "https://publicintelligence.net/fbi-defense-contractor-intrusions/"
                date = "2021/03/08"
        strings:
                $s1 = "WebServices.InitalizeWebServices" nocase
                $s2 = "Import Namespace=" nocase
        condition:
                2 of ($s*)

}



rule generic_php_shell {
        meta:
                description = "Generic php shell keyword detects"
                author = "Keven Murphy"
                reference = "not set"
                date = "2020/02/19"
        strings:
                $s0 = "eval" nocase
                $s1 = "<?php" nocase
                $s2 = "POST" nocase
                $s3 = "system" nocase
                $s4 = "shell" nocase
                $s5 = "passthru" nocase
                $s6 = "proc_open" nocase
                $s7 = "popen" nocase
                $s8 = "pcntl" nocase
                $s9 = "assert" nocase
                $s10 = "file_put_contents" nocase
                $s11 = "exec(" nocase
                $s12 = "shell_exe" nocase
                $s13 = "rot13" nocase
                $s14 = "phpinfo" nocase
                $s15 = "base64" nocase
                $s16 = "chmod" nocase
                $s17 = "mkdir" nocase
                $s18 = "fopen" nocase
                $s19 = "fclose" nocase
                $s20 = "readfile" nocase
                $s21 = "sockopen" nocase
                $s22 = "stream" nocase
                $s23 = "socket" nocase
                $s24 = "client" nocase 
                $s25 = "extract" nocase
                $s26 = "gzinflate" nocase
                $s27 = "gzuncompress" nocase
                $s28 = "preg_replace" nocase
                $s29 = "stripslash" nocase
                $s30 = "strrev" nocase
                $s31 = "unescape" nocase
                $s32 = "stripslash" nocase
                $s33 = "preg_match" nocase
                $s34 = "str_replace" nocase
                $s35 = "strrev" nocase
        condition:
                8 of ($s*)
}

rule chopper_generic_jsp {
        meta:
                description = "Generic jsp chopper shell detects"
                author = "Keven Murphy"
                reference = "not set"
                date = "2020/02/19"
        strings:
                $s0 = "eval" nocase
                $s1 = "write(" nocase
                $s2 = "FileOutputStream" nocase
                $s3 = "request.getParameter" nocase
                $s4 = "page import=\"" nocase
                $s5 = "java.util.*" nocase
                $s6 = "java.io.*" nocase
                $s7 = "println" nocase
                $s8 = "readLine" nocase 
                $s9 = "openConnection(" nocase
                $s10 = "exec(" nocase
                $s11 = "Runtime" nocase
                $s12 = "exec(" nocase
                $s13 = "getRuntime(" nocase
                $s14 = "Requst.item" nocase
                $s15 = "unsafe" nocase
        condition:
                3 of ($s*)
}

rule APT34_TwoFace_Loader_v11 : IRAN THREAT ACTOR {
        meta:
                description = "Detects APT34 TwoFace webshell loader"
                author = "Emanuele De Lucia"
                tlp = "white"
        strings:
                $ = "System.Convert.FromBase64String(" fullword ascii
                $ = "System.IO.File.WriteAllBytes(" ascii
                $ = "else if(Request.Form.Count==" ascii
                $ = "Request.ServerVariables[\"PATH_TRANSLATED\"].Substring" ascii
        condition:
                uint16(0) == 0x253c and all of them
}

rule APT34_TwoFace_Payload_v04 : IRAN THREAT ACTOR {
        meta:
                description = "Detects APT34 TwoFace webshell payload"
                author = "Emanuele De Lucia"
                tlp = "white"
        strings:
                $ = "//wmic /node:localhost process call create \"\"cmd.exe /c wmic" fullword ascii
                $ = "exec(string.Format(@\"wmic /node:{0}" ascii
                $ = "tfil" fullword ascii
                $ = "ttar" fullword ascii
                $ = "ttim" fullword ascii
                $ = "Convert.ToBase64String(new System.Security.Cryptography" fullword ascii
        condition:
                ( uint16(0) == 0xbbef and filesize < 200KB and all of them )
}
