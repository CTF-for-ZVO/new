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
