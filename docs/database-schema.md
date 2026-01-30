# Схема базы данных

SQLite, один файл БД (см. `DATABASE_PATH`).

## Таблицы

### `users`
Хранит пользователей по хешу Telegram ID (без хранения сырого ID).

| Колонка           | Тип    | Описание                    |
|-------------------|--------|-----------------------------|
| id                | INTEGER| PRIMARY KEY AUTOINCREMENT  |
| telegram_id_hash  | TEXT   | UNIQUE, SHA-256 hex         |
| created_at        | TEXT   | ISO 8601 datetime           |

**Индексы:** UNIQUE на `telegram_id_hash`.

---

### `scans`
Одна запись — одна проверка (ссылка, файл или голосовое).

| Колонка    | Тип    | Описание                              |
|------------|--------|---------------------------------------|
| id         | INTEGER| PRIMARY KEY AUTOINCREMENT            |
| user_id    | INTEGER| NOT NULL, FK → users(id)              |
| scan_type  | TEXT   | NOT NULL: 'url', 'file', 'voice'      |
| object_hash| TEXT   | Хеш URL или файла для кэша VT         |
| status     | TEXT   | NOT NULL: pending, scanning, completed, error |
| created_at | TEXT   | NOT NULL, ISO 8601                    |

**Индексы:**
- `(user_id, created_at)` — история по пользователю и месяцу;
- `(object_hash)` — поиск кэша VirusTotal.

---

### `virustotal_results`
Результаты VirusTotal; кэш по `object_hash` (URL или файл).

| Колонка        | Тип    | Описание                    |
|----------------|--------|-----------------------------|
| id             | INTEGER| PRIMARY KEY AUTOINCREMENT   |
| scan_id        | INTEGER| NOT NULL, FK → scans(id)    |
| object_hash    | TEXT   | NOT NULL, URL/file hash     |
| object_type    | TEXT   | NOT NULL: 'url', 'file'     |
| virustotal_data| TEXT   | NOT NULL, JSON              |
| cached_at      | TEXT   | NOT NULL, ISO 8601          |

**Индексы:**
- `(object_hash)` — поиск кэша перед новым сканированием;
- `(scan_id)` — связь со сканом.

---

### `llm_analysis`
Результат анализа LLM по одному скану (один к одному).

| Колонка      | Тип    | Описание                         |
|--------------|--------|----------------------------------|
| id           | INTEGER| PRIMARY KEY AUTOINCREMENT        |
| scan_id      | INTEGER| NOT NULL UNIQUE, FK → scans(id)  |
| threat_type  | TEXT   | NOT NULL: phishing, malware, scam, suspicious, clean |
| risk_level   | TEXT   | NOT NULL: low, medium, high      |
| explanation  | TEXT   | Краткое объяснение для юзера    |
| analysis_data| TEXT   | JSON от LLM                      |
| created_at   | TEXT   | NOT NULL, ISO 8601               |

**Индексы:** UNIQUE на `scan_id`.

---

### `files`
Метаданные загруженных файлов по скану (временное хранение пути до обработки).

| Колонка   | Тип    | Описание                    |
|-----------|--------|-----------------------------|
| id        | INTEGER| PRIMARY KEY AUTOINCREMENT   |
| scan_id   | INTEGER| NOT NULL, FK → scans(id)     |
| file_path | TEXT   | NOT NULL                    |
| file_hash | TEXT   | NOT NULL, SHA-256           |
| mime_type | TEXT   | MIME-тип                    |
| size      | INTEGER| Размер в байтах             |
| created_at| TEXT   | NOT NULL, ISO 8601          |

**Индексы:** `(scan_id)`.

---

## Хранение данных

- Данные пользователей и сканов хранятся не более **6 месяцев** (`DATA_RETENTION_DAYS`).
- Очистка выполняется функцией `cleanup_old_data()` (удаление записей старше N дней и связанных VT/LLM/files).
