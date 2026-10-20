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

/*
  Reguli generice pentru payload-uri care NU evalueaza pe server, ci injecteaza
  JavaScript ofuscat in pagina sau isi ascund prezenta. Prind forma, nu un
  string anume (ex. wp-warden), deci prind si variante viitoare. Semnal pentru
  triaj, nu sentinta: o biblioteca legitima poate coda resurse, un plugin poate
  emite script. De aceea conditia cere mai multe indicii simultan.
*/

rule soc_php_injects_obfuscated_js
{
    meta:
        description = "PHP care injecteaza in pagina un bloc JavaScript ofuscat (skimmer / redirect / C2 client-side)"
        mitre = "T1059.007"
        severity = "high"
    strings:
        $php = "<?" ascii
        // emite un <script> in iesire, adesea rupt ca sa evite cautarea naiva
        $s1 = /echo\s+['"]<scr['"]\s*\.\s*['"]ipt/ nocase
        $s2 = "<script>" ascii nocase
        $s3 = /header\s*\(\s*['"]\s*Content-Type:\s*(application|text)\/javascript/ nocase
        // marcaje de deobfuscator JS in continutul emis
        $d1 = "fromCharCode" ascii
        $d2 = "charCodeAt" ascii
        $d3 = /\[\s*['"]String['"]\s*\]\s*\[\s*['"]fromCharCode['"]\s*\]/ ascii
        $d4 = "TextDecoder" ascii
    condition:
        $php and any of ($s*) and 2 of ($d*)
}

rule soc_php_self_hiding_plugin
{
    meta:
        description = "Plugin WordPress care se ascunde singur din lista de plugin-uri (persistenta ascunsa)"
        mitre = "T1562.001"
        severity = "high"
    strings:
        $php = "<?" ascii
        $f = /add_filter\s*\(\s*['"]all_plugins['"]/ nocase
        $u = /unset\s*\(\s*\$\w+\s*\[\s*plugin_basename\s*\(\s*__FILE__/ nocase
    condition:
        $php and $f and $u
}

rule soc_php_encoded_payload_blob
{
    meta:
        description = "PHP cu un bloc mare codat (base64/gz) decodat la runtime - payload incorporat, nu neaparat eval"
        mitre = "T1027"
        severity = "medium"
    strings:
        $php = "<?" ascii
        $dec = /\b(base64_decode|gzinflate|gzuncompress|gzdecode|hex2bin|str_rot13)\s*\(/ nocase
        $blob = /[A-Za-z0-9+\/]{1000,}/ ascii
        $heredoc = /<<<['"]?_?[A-Za-z0-9]*B64/ ascii
    condition:
        $php and $dec and ($blob or $heredoc)
}

rule soc_php_nopriv_ajax_serves_js
{
    meta:
        description = "Endpoint AJAX WordPress accesibil anonim care serveste JavaScript"
        mitre = "T1105"
        severity = "medium"
    strings:
        $php = "<?" ascii
        $nopriv = "wp_ajax_nopriv_" ascii
        $js = /Content-Type:\s*(application|text)\/javascript/ nocase
    condition:
        $php and $nopriv and $js
}
