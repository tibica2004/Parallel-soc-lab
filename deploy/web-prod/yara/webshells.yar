/*
  Reguli YARA pentru webshell-uri PHP in webroot (faza 12). Scrise de noi, mici
  si explicabile: cod care executa ce vine din cererea HTTP, payload-uri ascunse
  prin codare si marcaje ale webshell-urilor cunoscute. Nu prind tot; prind
  forma comuna. Rezultatul e un semnal pentru triaj, nu o sentinta.
*/

rule soc_php_exec_request_input
{
    meta:
        description = "PHP executa comenzi primite direct din cererea HTTP"
        mitre = "T1505.003"
        severity = "high"
    strings:
        $php = "<?" ascii
        $exec = /\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $bt = /`\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        $php and ($exec or $bt)
}

rule soc_php_eval_request_input
{
    meta:
        description = "PHP evalueaza cod primit din cererea HTTP"
        mitre = "T1505.003"
        severity = "high"
    strings:
        $php = "<?" ascii
        $eval = /\b(eval|assert|create_function)\s*\(\s*(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $cb = /\b(call_user_func|call_user_func_array|array_map|usort)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $preg_e = /preg_replace\s*\(\s*['"].{1,40}\/e['"]\s*,\s*\$_(GET|POST|REQUEST)/ nocase
    condition:
        $php and any of ($eval, $cb, $preg_e)
}

rule soc_php_obfuscated_eval
{
    meta:
        description = "PHP evalueaza un payload ascuns prin codare (base64, gzip, rot13)"
        mitre = "T1027"
        severity = "high"
    strings:
        $php = "<?" ascii
        $o1 = /\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin)\s*\(/ nocase
        $o2 = /\beval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(/ nocase
        $o3 = /\bassert\s*\(\s*(base64_decode|str_rot13)\s*\(/ nocase
    condition:
        $php and any of ($o*)
}

rule soc_php_reverse_shell
{
    meta:
        description = "PHP deschide o conexiune de retea si leaga un shell de ea"
        mitre = "T1059.004"
        severity = "critical"
    strings:
        $php = "<?" ascii
        $sock = /\bfsockopen\s*\(/ nocase
        $proc = /\b(proc_open|shell_exec|exec|system|popen)\s*\(/ nocase
        $sh = /\/bin\/(ba)?sh\b/ ascii
    condition:
        $php and $sock and $proc and $sh
}

rule soc_known_webshell_markers
{
    meta:
        description = "Marcaje ale webshell-urilor PHP cunoscute"
        mitre = "T1505.003"
        severity = "critical"
    strings:
        $a = "b374k" ascii nocase
        $b = "c99shell" ascii nocase
        $c = "r57shell" ascii nocase
        $d = "WSO " ascii
        $e = "FilesMan" ascii
        $f = "Weevely" ascii nocase
        $g = "p0wny" ascii nocase
    condition:
        uint16(0) == 0x3f3c and any of them
}
