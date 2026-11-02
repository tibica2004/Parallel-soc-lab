<?php
// Test semgrep: doar forma vulnerabila minima si varianta corecta. Fara payload.

function soc_test_exec_bad() {
    // ruleid: wp-dangerous-exec
    $out = shell_exec('uptime');
    return $out;
}

function soc_test_exec_bad_eval($code) {
    // ruleid: wp-dangerous-exec
    return eval($code);
}

function soc_test_exec_ok() {
    // ok: wp-dangerous-exec
    return sys_getloadavg();
}
