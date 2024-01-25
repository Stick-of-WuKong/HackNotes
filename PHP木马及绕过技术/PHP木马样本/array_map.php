<?php
highlight_file(__FILE__);
error_reporting(0);
$cmd = $_POST['cmd'];
$arg = $_POST['arg'];
array_map($cmd,$arg);
?>