# Запуск Backuply как фонового Linux-сервиса

Первый этап использует один источник на папку. Перед установкой подготовьте
конфигурацию двух устройств по [README](../README.md). Для обычной LAN достаточно
доступности TCP-порта 24800 между разрешёнными устройствами; внешние серверы
для работы сервиса не требуются.

## Установка

Команды ниже предназначены для администратора целевой машины. В процессе
разработки сервис не устанавливается автоматически в систему пользователя.

```sh
go build -trimpath -o bin/backuply ./cmd/backuply
sudo useradd --system --home-dir /var/lib/backuply --shell /usr/sbin/nologin backuply
sudo install -m 0755 bin/backuply /usr/local/bin/backuply
sudo install -d -m 0750 -o root -g backuply /etc/backuply
sudo install -d -m 0700 -o backuply -g backuply /var/lib/backuply
sudo install -d -m 0750 -o backuply -g backuply /srv/backuply
sudo -u backuply /usr/local/bin/backuply init -state-dir /var/lib/backuply
```

Если системный пользователь уже создан, пропустите `useradd`. Сохраните Device ID,
создайте ID на второй машине и внесите оба отпечатка в соответствующие конфиги.
Отредактируйте копию [примера](../examples/backuply.conf): замените адрес интерфейса,
адрес peer, `device_id`, путь папки и источник. Пользователю `backuply` нужны права
чтения источника и записи в папку получателя; команда `init` также создаёт marker.

```sh
sudo install -m 0640 -o root -g backuply examples/backuply.conf /etc/backuply/backuply.conf
sudo -u backuply /usr/local/bin/backuply check -config /etc/backuply/backuply.conf
sudo -u backuply /usr/local/bin/backuply init -config /etc/backuply/backuply.conf
sudo install -m 0644 deploy/systemd/backuply.service /etc/systemd/system/backuply.service
sudo systemctl daemon-reload
sudo systemctl enable --now backuply
```

Устанавливайте уже отредактированный пример: placeholder вместо `device_id`
намеренно не проходит проверку. Готовый unit разрешает запись в `/var/lib/backuply`
и `/srv/backuply`, скрывает домашние каталоги и ограничивает остальную ФС чтением.
Если выбраны другие пути, скорректируйте `ReadWritePaths` и `ProtectHome` через
`systemctl edit backuply`. Эти настройки не выдают Unix-права на файлы; права
и группы на папках настраиваются отдельно. Не меняйте владельца существующего
дерева проектов рекурсивно без необходимости.

## Управление

```sh
sudo systemctl status backuply
sudo -u backuply /usr/local/bin/backuply status -config /etc/backuply/backuply.conf
sudo journalctl -u backuply -f
sudo systemctl restart backuply
sudo systemctl stop backuply
```

Демон пишет структурированные журналы в stderr, systemd сохраняет их в journal.
SIGTERM отменяет синхронизацию, закрывает сессии и SQLite, освобождает блокировку.
Неполученный блок не становится итоговым файлом. После рестарта идентичность и
индекс читаются с диска. Отсутствующая/повреждённая identity вызывает ошибку;
сервис никогда не генерирует новый ключ незаметно вместо старого.

`status` возвращает успех, если отвечает демон; проверяйте `folders.*.last_error`
для состояния синхронизации. Недоступный peer повторно опрашивается с интервалом
`scan_interval`. В первом этапе интервал постоянный, без экспоненциального backoff.
SIGHUP/hot reload пока нет: сначала `check`, затем `systemctl restart`.

## Формат конфигурации

INI-секции `[service]`, `[peer "имя"]`, `[folder "id"]`; имена состоят из ASCII
букв/цифр, точки, дефиса и подчёркивания и начинаются с буквы/цифры.
Комментарии `#` или `;` занимают всю строку. Значения можно заключать в двойные
кавычки; подстановки переменных окружения и `~` нет. Неизвестные и повторные ключи
или секции считаются ошибкой. Пути абсолютные, рабочие папки и `state_dir`
не должны совпадать или быть вложенными друг в друга.

| Секция | Параметр | Значение |
| --- | --- | --- |
| service | listen | По умолчанию `127.0.0.1:24800`; `:0` допустим для тестового динамического порта |
| service | state_dir | Обязательный отдельный каталог identity, SQLite, lock и control socket |
| service | scan_interval | По умолчанию `5s`, минимум `100ms`; полный периодический обход |
| peer | address | Обязательный `host:port`, например `192.168.1.20:24800` или `[fd00::2]:24800` |
| peer | device_id | SHA-256 сертификата удалённого устройства: 64 символа в нижнем регистре |
| folder | path | Абсолютный путь локальной папки |
| folder | source | Обязательно: `local` либо имя peer из списка этой папки |
| folder | peers | Имена разрешённых участников через запятую; для пока не расшаренного источника список может быть пустым |

Идентичность проверяется отдельно от адреса: перенос устройства на другой IP
не требует смены ключа. Сертификат сейчас создаётся на 10 лет; автоматической
ротации нет. При смене сертификата новый ID нужно явно внести у peers.

## Основания реализации

Изучены первичные документы: [Go TLS](https://pkg.go.dev/crypto/tls),
[сигналы и отмена Go](https://pkg.go.dev/os/signal#NotifyContext),
[SQLite WAL](https://www.sqlite.org/wal.html),
[драйвер modernc](https://pkg.go.dev/modernc.org/sqlite),
[защита путей os.Root](https://go.dev/blog/osroot),
[официальный исходник документации systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml).
Это обосновывает взаимную аутентификацию, завершение через контекст, локальное
хранение SQLite и операции с путями относительно открытого корня.
