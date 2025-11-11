<?php

$servername = "db";
$username = "lotto_user";
$password = "lotto_pAss_0Rd";
$dbname = "lotto_db";


$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$conn->query("SET SESSION max_statement_time = 2;");


function generate_lotto_data($conn) {
    $result = $conn->query("SELECT COUNT(*) as count FROM lotto_results");
    $row = $result->fetch_assoc();
    if ($row['count'] > 0) {
        return;
    }

    echo "<p>Генеруємо 1000 історичних лотерейних ігор...</p>";

    $stmt_insert = $conn->prepare("INSERT INTO lotto_results (draw_date, num1, num2, num3, num4, num5, num6) VALUES (?, ?, ?, ?, ?, ?, ?)");
    

    $current_date = strtotime('2024-01-01');
    
    for ($i = 0; $i < 1000; $i++) {
        $draw_date = date('Y-m-d', $current_date + ($i * 86400)); // Кожен день
        
        
        $numbers = range(1, 36);
        shuffle($numbers);
        $draw_nums = array_slice($numbers, 0, 6);
        sort($draw_nums);
        
        
        $stmt_insert->bind_param("siiiiii", $draw_date, $draw_nums[0], $draw_nums[1], $draw_nums[2], $draw_nums[3], $draw_nums[4], $draw_nums[5]);
        $stmt_insert->execute();
    }
    
    $stmt_insert->close();
    echo "<p>Генерація завершена. Таблиця заповнена!</p>";
}

generate_lotto_data($conn);

$output = "";
$user_input_string = "";

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['numbers'])) {
    $user_input = $_POST['numbers'];
    $user_input = preg_replace("/sleep|benchmark/i", " ", $user_input);
    $user_input_string = $user_input; // Зберігаємо для відображення

    $vulnerable_query = "
        SELECT 
            draw_date, 
            (
                (num1 IN ({$user_input})) + (num2 IN ({$user_input})) + 
                (num3 IN ({$user_input})) + (num4 IN ({$user_input})) + 
                (num5 IN ({$user_input})) + (num6 IN ({$user_input}))
            ) AS matches
        FROM lotto_results
        ORDER BY matches DESC
        LIMIT 1
    ";

    
    $result = $conn->query($vulnerable_query);

    if ($result === FALSE) {
        $output = "<p class='error'>Помилка запиту: " . $conn->error . "</p>";
    } elseif ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $matches = (int)$row['matches'];
        $date = $row['draw_date'];

        if ($matches == 6) {
            $output = "
                <p class='success'>🎉 <b>ВІТАЄМО!</b> 🎉</p>
                <p>Ви б виграли головний приз у день <b>{$date}</b>, вгадавши всі 6 чисел!</p>
            ";
        } else {
            $output = "
                <p class='info'>Співпадіння неповне.</p>
                <p>Ваше найкраще співпадіння було <b>{$matches}</b> чисел у день <b>{$date}</b>.</p>
                <p>Спробуйте ще раз, щоб знайти 6!</p>
            ";
        }
    } else {
        $output = "<p class='error'>Не вдалося знайти результати.</p>";
    }
}
?>

<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>CTF Лотерея: Перевір Удачу</title>
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
        <h1>🔢 CTF Лотерея: Вгадай Комбінацію</h1>
        <p>Введіть <b>6 чисел</b> через кому (від 0 до 36), щоб дізнатися, чи виграли б ви, та коли було найкраще співпадіння.</p>
        <p>Приклад: <code>1,5,10,15,20,25</code></p>
        
        <form method="POST">
            <label for="numbers">Ваші числа:</label>
            <input type="text" id="numbers" name="numbers" value="<?php echo htmlspecialchars($user_input_string); ?>" required>
            <button type="submit">Перевірити</button>
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