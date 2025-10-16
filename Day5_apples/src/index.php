<?php
// 1. Визначення поточної сторінки
// Перевіряємо, чи встановлена змінна 'page' у URL (наприклад, index.php?page=bilyi_naliv)
$page = isset($_GET['page']) ? $_GET['page'] : 'home';

// 2. Асоціативний масив для безпечного підключення
// Ключ: ім'я в URL (GET-параметр)
// Значення: шлях до файлу контенту
$pages = [
    'home' => 'pages/home.php',
    'bilyi_naliv' => 'pages/sort_bilyi_naliv.php',
    'slava_peremozhtsiam' => 'pages/sort_slava_peremozhtsiam.php',
    'spartak' => 'pages/sort_spartak.php',
    'renet_symyrenka' => 'pages/sort_renet_symyrenka.php',
];

// 3. Перевірка, чи існує запитувана сторінка
// якщо не існує, то віддаємо сторінку, яку запитували (це вразливість)
$content_file = $pages[$page] ?? $page;

// Функція для генерації посилання в меню
function generate_link($link_key, $text) {
    // Додаємо клас 'active' для поточної сторінки
    global $page;
    $class = ($page === $link_key) ? 'active' : '';
    // Формуємо URL: index.php?page=link_key
    return "<li class='$class'><a href='index.php?page=$link_key'>$text</a></li>";
}
?>

<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <title>Українські Сорти Яблук</title>
    <style>
        body { font-family: sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }
        header { background-color: #a30000; color: white; padding: 20px; text-align: center; }
        nav { background-color: #e6e6e6; padding: 10px 0; }
        nav ul { list-style: none; padding: 0; margin: 0; display: flex; justify-content: center; }
        nav li { margin: 0 15px; }
        nav a { text-decoration: none; color: #333; padding: 5px 10px; display: block; border-radius: 5px; }
        nav a:hover, nav li.active a { background-color: #c0c0c0; color: #000; font-weight: bold; }
        .container { max-width: 900px; margin: 20px auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        h2 { color: #550000; border-bottom: 2px solid #ccc; padding-bottom: 10px; }
        article { line-height: 1.6; }
        footer { text-align: center; padding: 10px; background-color: #a30000; color: white; margin-top: 20px; }
    </style>
</head>
<body>

    <header>
        <h1>Сорти Українських Яблук 🇺🇦</h1>
    </header>

    <nav>
        <ul>
            <?php
            // Генеруємо меню за допомогою нашої функції
            echo generate_link('home', 'Головна');
            echo generate_link('bilyi_naliv', 'Білий налив');
            echo generate_link('slava_peremozhtsiam', 'Слава переможцям');
            echo generate_link('spartak', 'Спартак');
            echo generate_link('renet_symyrenka', 'Ренет Симиренка');
            ?>
        </ul>
    </nav>

    <div class="container">
        <?php
        // 4. Підключення контенту
        // Це основний момент, де відбувається підключення сторінок
        include $content_file;
        ?>
    </div>

    <footer>
        &copy; <?php echo date("Y"); ?> Яблучний каталог
    </footer>

</body>
</html>
