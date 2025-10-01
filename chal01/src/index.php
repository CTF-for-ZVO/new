<?php
if (isset($_GET['file'])) {
    include($_GET['file']);
} else {
    echo "Please specify a file to view. Example: ?file=index.php";
}
?>
