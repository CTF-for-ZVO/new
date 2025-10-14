<?php
if (isset($_GET['ip'])) {
    if (preg_match('/[\|&\$ ]/', $_GET['ip'])) {
        die("Error: Invalid host or IP address.");
}

    print_r(shell_exec('ping -c 1 '.$_GET['ip']));
} else {
    echo "Something went wrong";
}
?>
