<?php
// Налаштування з'єднання з БД
$servername = "db"; 
$username = "lotto_user";
$password = "lotto_pAss_0Rd";
$dbname = "lotto_db";

$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// 🛡️ ЗАХИСТ: Встановлюємо тайм-аут запиту (2 секунди)
$conn->query("SET SESSION max_statement_time = 2;");

// --- Функція генерації випадкових 1000 ігор ---
function generate_lotto_data($conn) {
    $result = $conn->query("SELECT COUNT(*) as count FROM lotto_results");
    $row = $result->fetch_assoc();
    if ($row['count'] > 0) {
        return; 
    }
    
    $stmt_insert = $conn->prepare("INSERT INTO lotto_results (draw_date, num1, num2, num3, num4, num5, num6) VALUES (?, ?, ?, ?, ?, ?, ?)");
    
    $current_date = strtotime('2024-01-01');
    
    for ($i = 0; $i < 1000; $i++) {
        $draw_date = date('Y-m-d', $current_date + ($i * 86400));
        
        $numbers = range(0, 36);
        shuffle($numbers);
        $draw_nums = array_slice($numbers, 0, 6);
        sort($draw_nums);
        
        $stmt_insert->bind_param("siiiiii", $draw_date, $draw_nums[0], $draw_nums[1], $draw_nums[2], $draw_nums[3], $draw_nums[4], $draw_nums[5]);
        $stmt_insert->execute();
    }
    
    $stmt_insert->close();
}

generate_lotto_data($conn);

$output = "";
$user_input_string = "";
$default_date = '2025-01-05'; // Початкова дата для прикладу

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['draw_date'])) {
    
    $user_input = $_POST['draw_date'];
    $user_input_string = $user_input; 
    

    $vulnerable_query = "
        SELECT num1, num2, num3, num4, num5, num6
        FROM lotto_results
        WHERE draw_date = '{$user_input}'
        LIMIT 1
    ";

    $result = $conn->query($vulnerable_query);

    if ($result === FALSE) {
        $output = "<p class='error'>Помилка запиту або тайм-аут: " . $conn->error . "</p>";
    } elseif ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
        $numbers = implode(', ', $row);

        
        $output = "
            <p class='success'>✅ Результат для дати <b>{$user_input}:</b></p>
            <p>Виграшна комбінація: <b>{$numbers}</b></p>
        ";
    } else {
        $output = "
            <p class='info'>🤔 Немає результатів для дати <b>{$user_input}</b>.</p>
            <p>Спробуйте іншу дату або перевірте формат.</p>
        ";
    }
}
?>

<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>CTF Лотерея: Перевірка Дати</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        label { display: block; margin-bottom: 8px; font-weight: bold; }
        input[type="text"] { width: 95%; padding: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px; }
        button { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .info { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .error { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📅 CTF Лотерея: Перевірка Дати</h1>
        <p>Введіть дату розіграшу у форматі YYYY-MM-DD, щоб отримати виграшну комбінацію за цей день. </p>
        <p>Наприклад: <code><?php echo $default_date; ?></code></p>
        
        <form method="POST">
            <label for="draw_date">Дата розіграшу:</label>
            <input type="text" id="draw_date" name="draw_date" value="<?php echo htmlspecialchars($user_input_string ?: $default_date); ?>" required>
            <button type="submit">Перевірити Дату</button>
        </form>

        <?php if (!empty($output)): ?>
            <div class="result">
                <?php echo $output; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>

<?php
$conn->close();
?>