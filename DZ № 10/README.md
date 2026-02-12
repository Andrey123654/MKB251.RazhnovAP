Отчет по уязвимости CVE-2026-21508
1. ОПИСАНИЕ УЯЗВИМОСТИ

CVE-2026-21508 — уязвимость повышения привилегий (Local Privilege Escalation) в Windows Storage API, обнаруженная и опубликованная исследователем 0xc4r в феврале 2026 года.

Суть уязвимости:
Уязвимость позволяет непривилегированному пользователю заставить процесс WUDFHost.exe (Windows Driver Foundation), работающий с привилегиями LOCAL SERVICE, загрузить произвольную DLL-библиотеку путем манипуляции COM-объектами через функцию _SHCoCreateInstance из windows.storage.dll.

Корень проблемы:
Некорректная обработка реестровых путей в _SHCoCreateInstance. Функция использует HKEY_CLASSES_ROOT с кэшированным дескриптором, который указывает на пользовательский реестр (HKCU\Software\Classes), когда процесс имперсонирует пользователя. Это позволяет атакующему перенаправить создание COM-объекта на произвольный CLSID.

Вектор атаки:

    Подключенный USB-накопитель с хотя бы одним JPG-файлом

    Запуск Windows Media Player (wmplayer.exe) как триггер

    WUDFHost.exe обнаруживает USB и инициирует вызов _SHCoCreateInstance

    Через подмену реестра атакующий перенаправляет создание COM-объекта на {E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496}

    WUDFHost.exe загружает DLL из %PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll

Привилегии:

    Исходные: WUDFHost.exe (NT AUTHORITY\LOCAL SERVICE)

    После RevertToSelf(): WUDFHost.exe (LOCAL SERVICE без имперсонализации)

    Возможность эскалации: LOCAL SERVICE → SYSTEM (через SeImpersonatePrivilege)

Ключевые CLSID:

    {F5FB2C77-0E2F-4A16-A381-3E560C68BC83} — исходный CLSID, перехватываемый в реестре

    {E9F83CF2-E0C0-4CA7-AF01-E90C70BEF496} — целевой CLSID (Cross Device Virtual Camera Source)

    {ADD8BA80-002B-11D0-8F0F-00C04FD7D062} — интерфейсный IID

Затронутые версии: Windows 10, Windows 11 (подтверждено на Windows 11)

Полный PoC: https://github.com/0xc4r/CVE-2026-21508_POC
