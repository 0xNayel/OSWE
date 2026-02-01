<?php
/*
@title Helper script for token_spray.py
Usage: php token_list.php <time_start> <time_end>
*/
function generateToken($seed) {
    srand($seed);
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
    $ret = '';
    for ($i = 0; $i < 32; $i++) {
        $ret .= $chars[rand(0,strlen($chars)-1)];
    }
    return $ret;
}

$t_start = $argv[1];
$t_end   = $argv[2];

$filename = "tokens.txt";
$file = fopen($filename, "w");  // open file for writing (overwrite mode)

for ($i = $t_start; $i < $t_end; $i++) {
    fwrite($file, generateToken($i) . "\n");
}

fclose($file);

echo "[+] Tokens saved to $filename\n";
?>
