bind = "0.0.0.0:5000"
workers = 4
threads = 2
worker_class = "gthread"
timeout = 60
graceful_timeout = 30

# Перезапуск воркеров после N запросов: страхует от накопления утечек памяти
# и зависших потоков за недели аптайма. jitter разводит перезапуски во времени.
max_requests = 1000
max_requests_jitter = 100

# Разрывает keep-alive соединения, которые клиент бросил
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = "info"
