<?php
highlight_file(__FILE__);
error_reporting(0);
$func = $_POST['func'];
$arg = $_POST['arg'];
array_user_func_array($func,$arg);
?>