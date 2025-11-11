CREATE TABLE IF NOT EXISTS lotto_results (
    game_id INT AUTO_INCREMENT PRIMARY KEY,
    draw_date DATE NOT NULL,
    num1 INT NOT NULL,
    num2 INT NOT NULL,
    num3 INT NOT NULL,
    num4 INT NOT NULL,
    num5 INT NOT NULL,
    num6 INT NOT NULL
);

CREATE UNIQUE INDEX idx_draw_date ON lotto_results (draw_date);

CREATE TABLE IF NOT EXISTS flag (
    flag_value VARCHAR(255)
);

INSERT INTO flag (flag_value) VALUES ('CTF{Simple_SQLi_W0rks_L1k3_a_Charm}');







CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(32) NOT NULL, -- MD5 хеш завжди 32 символи
    is_admin BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    old_password_plain VARCHAR(255) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);



INSERT INTO users (username, password_hash, is_admin) VALUES
('alice', MD5('flag{12345678}'), 0),
('bob', MD5('flag{12345678}'), 0),
('charlie', MD5('flag{12345678}'), 0),
('david', MD5('flag{12345678}'), 0),
('eve', MD5('flag{12345678}'), 0),
('fiona', MD5('flag{12345678}'), 0),
('george', MD5('flag{12345678}'), 0),
('hannah', MD5('flag{12345678}'), 0),
('ivan', MD5('flag{12345678}'), 0),
('julia', MD5('flag{12345678}'), 0),
('klaus', MD5('flag{12345678}'), 0),
('linda', MD5('flag{12345678}'), 0),
('mike', MD5('flag{12345678}'), 0),
('nora', MD5('flag{12345678}'), 0),
('oscar', MD5('flag{12345678}'), 0),
('paula', MD5('flag{12345678}'), 0),
('quentin', MD5('flag{12345678}'), 0),
('rachel', MD5('flag{12345678}'), 0),
('steve', MD5('flag{12345678}'), 0);

INSERT INTO users (username, password_hash, is_admin) VALUES
('admin', MD5('flag{13371337}'), 1);


INSERT INTO password_history (user_id, old_password_plain) VALUES
(20, 'flag{13351335}'),  
(20, 'flag{13361336}');  