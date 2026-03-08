1. ОБЩАЯ ИНФОРМАЦИЯ

Описание итогового домашнего задания по дисциплине Программирование на Python.


2. ЦЕЛЬ И ЗАДАЧИ СКРИПТА

2.1. Основная цель

Создание инструмента для автоматизированного анализа логов безопасности, выявления угроз, имитации реагирования и формирования отчетности.

2.2. Задачи

    Сбор данных из логов Suricata и Nessus

    Анализ данных с выявлением потенциальных угроз

    Обогащение данных через VirusTotal API

    Реагирование на угрозы (имитация блокировки IP)

    Формирование отчетов в форматах JSON и CSV

    Визуализация результатов в виде графиков PNG

3. ИСПОЛЬЗУЕМЫЕ ТЕХНОЛОГИИ

3.1. Библиотеки Python

Библиотека	Назначение

os	Работа с файловой системой и переменными окружения

json	Парсинг и создание JSON-файлов

re	Регулярные выражения для парсинга логов

requests	Отправка HTTP-запросов к API VirusTotal

pandas	Обработка и анализ табличных данных

matplotlib	Создание графиков и визуализация

datetime	Работа с датами и временем

collections.Counter	Подсчет частоты элементов

3.2. Внешние сервисы и API

    VirusTotal API v3 - проверка IP-адресов на вредоносность

    Логи Suricata - события сетевой безопасности (формат JSON)

    Логи Nessus - SSH атаки и уязвимости (формат syslog)

4.2. Модули и их функции
Модуль/Класс	Метод	Функция
ThreatAnalyzer	load_suricata_alerts()	Загрузка JSON-логов Suricata
	parse_nessus_logs()	Парсинг syslog-логов Nessus
	analyze_threats()	Выявление угроз из данных
	check_ip_virustotal()	Проверка IP через VirusTotal
	enrich_with_virustotal()	Обогащение данных
	run()	Запуск полного анализа
IncidentResponder	respond()	Имитация блокировки IP и уведомлений
ReportGenerator	save_reports()	Сохранение JSON и CSV отчетов
	create_visualizations()	Создание PNG графиков
main	main()	Оркестрация всех этапов

5. ДЕТАЛЬНОЕ ОПИСАНИЕ ФУНКЦИЙ
5.1. Класс ThreatAnalyzer
__init__(self)

    Назначение: Инициализация анализатора

    Атрибуты:

        suricata_alerts: список алертов Suricata

        nessus_events: список событий Nessus

        threats: список найденных угроз

        vt_cache: кэш результатов VirusTotal

        stats: статистика анализа

load_suricata_alerts(self)

    Назначение: Загрузка и парсинг JSON-логов Suricata

    Поддерживаемые форматы:

        JSON массив [...]

        JSON Lines (построчный JSON)

    Обработка ошибок: Пропуск некорректных строк

parse_nessus_logs(self)

    Назначение: Парсинг syslog-логов Nessus

    Регулярное выражение: (\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)

    Извлекаемые поля: timestamp, host, service, pid, message, ip

    Определение типа события:

        invalid_user - невалидный пользователь

        failed_password - неудачная попытка входа

        connection_reset - сброс соединения

        log4shell_attempt - попытка эксплуатации Log4Shell

analyze_threats(self)

    Назначение: Выявление угроз из загруженных данных

    Анализ Suricata: Добавление IDS алертов

    Анализ Nessus: Добавление SSH-атак

    Выявление брутфорса: IP с множественными попытками

check_ip_virustotal(self, ip)

    Назначение: Проверка IP через VirusTotal API

    Параметры: ip - IP-адрес для проверки

    Возвращает: dict с результатами или None

    Кэширование: Результаты сохраняются в vt_cache

    Таймаут: 10 секунд на запрос

enrich_with_virustotal(self)

    Назначение: Обогащение данных результатами VirusTotal

    Сбор IP: Уникальные IP из найденных угроз

    Ограничение: Проверка первых 10 IP (для экономии времени)

    Добавление угроз: Вредоносные IP добавляются как отдельные угрозы

run(self)

    Назначение: Запуск полного цикла анализа

    Последовательность:

        Загрузка логов Suricata

        Загрузка логов Nessus

        Анализ угроз

        Обогащение через VirusTotal

        Вывод статистики

    Возвращает: список найденных угроз

5.2. Класс IncidentResponder
__init__(self, threats)

    Назначение: Инициализация обработчика инцидентов

    Параметры: threats - список найденных угроз

    Атрибуты:

        blocked_ips: множество заблокированных IP

        notifications: список уведомлений

respond(self)

    Назначение: Реагирование на угрозы (имитация)

    Логика:

        Отбор угроз с критичностью CRITICAL/HIGH

        Для каждой угрозы с IP:

            Проверка, не заблокирован ли IP

            Блокировка IP (добавление в blocked_ips)

            Создание уведомления

            Вывод в консоль

    Возвращает: dict с заблокированными IP и уведомлениями

5.3. Класс ReportGenerator
__init__(self, threats, response_data)

    Назначение: Инициализация генератора отчетов

    Параметры:

        threats - список угроз

        response_data - результаты реагирования

save_reports(self)

    Назначение: Сохранение отчетов

    JSON отчет: Полная информация с вложенной структурой

    CSV отчет: Табличный формат для анализа в Excel

    Статистика: Подсчет по критичности, источникам, типам

create_visualizations(self)

    Назначение: Создание графиков

    График 1 (4 в 1):

        Распределение по критичности

        Топ источников угроз

        Топ подозрительных IP

        Типы угроз (круговая диаграмма)

    График 2: Активность SSH атак по часам

5.4. Функция main()
main()

    Назначение: Основная точка входа

    Последовательность:

        Создание анализатора и запуск анализа

        Создание обработчика и реагирование

        Создание генератора и формирование отчетов

        Вывод финальной статистики

6. ФОРМАТЫ ВХОДНЫХ ДАННЫХ
6.1. Логи Suricata (alerts-only.json)
json

{
  "timestamp": "2015-03-29T11:01:38.221126-0600",
  "src_ip": "222.186.56.46",
  "dest_ip": "192.168.0.2",
  "alert": {
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak"
  }
}

6.2. Логи Nessus (log_example.txt)

Jan 20 22:54:47 demohost001 sshd[1762]: Connection reset by 192.168.0.15 port 52678 [preauth]
Jan 20 23:03:10 demohost001 sshd[3236]: Unable to negotiate with 192.168.0.15 port 56456: no matching key exchange method found. Their offer: ${jndi:ldap://log4shell-ssh.w.nessus.org/nessus} [preauth]

7. ФОРМАТЫ ВЫХОДНЫХ ДАННЫХ
7.1. JSON отчет (threat_report.json)
json

{
  "generated": "2026-03-08T15:30:45.123456",
  "total_threats": 887,
  "blocked_ips": ["192.168.0.15", "222.186.56.46"],
  "statistics": {
    "by_severity": {"CRITICAL": 5, "HIGH": 205, "MEDIUM": 572, "LOW": 105},
    "by_source": {"SSH Logs": 749, "Suricata IDS": 136, "VirusTotal": 2}
  },
  "threats": [...]
}

7.2. CSV отчет (threat_analysis.csv)
csv

source,timestamp,severity,ip,threat_type,details
Suricata IDS,2015-03-29T11:01:38.221126-0600,HIGH,222.186.56.46,IDS Alert,ET SCAN Potential SSH Scan
SSH Logs,Jan 20 23:03:10,CRITICAL,192.168.0.15,SSH_log4shell_attempt,Unable to negotiate...

7.3. Графики PNG

    threat_visualization.png - 4 графика в одном

    cvss_distribution.png - временной ряд SSH атак

8. ЛОГИКА ОПРЕДЕЛЕНИЯ УГРОЗ
8.1. Классификация по критичности
Уровень	Критерии	Примеры
🔴 CRITICAL	Log4Shell, VT malicious >3	Log4Shell атаки, подтвержденные вредоносные IP

🟠 HIGH	Failed password, IDS алерты	Неудачные попытки входа, сканирование

🟡 MEDIUM	Invalid user, Connection reset	Невалидные пользователи, сброс соединения

🟢 LOW	Normal events	Информационные события

8.2. Типы угроз

Тип	Источник	Описание
IDS Alert	Suricata	Обнаружение атак IDS
SSH_invalid_user	Nessus	Попытка входа под несуществующим пользователем
SSH_failed_password	Nessus	Неудачная попытка входа
SSH_connection_reset	Nessus	Сброс SSH соединения
SSH_log4shell_attempt	Nessus	Попытка эксплуатации Log4Shell
SSH_Brute_Force	Nessus	Множественные попытки с одного IP
Malicious_IP	VirusTotal	IP подтвержден как вредоносный


9. ЗАКЛЮЧЕНИЕ

Разработанный скрипт демонстрирует:

    Практическое применение навыков программирования на Python

    Интеграцию с внешними API (VirusTotal)

    Обработку различных форматов данных (JSON, syslog)

    Анализ и классификацию угроз безопасности

    Реагирование на инциденты (имитация)

    Формирование структурированных отчетов

    Визуализацию результатов анализа
