# Используем официальный Python образ
FROM python:3.10-slim

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY . .

# Делаем entrypoint скрипты исполняемыми
RUN chmod +x scripts/*.sh

# Экспонируем порт (будет использоваться Gunicorn)
EXPOSE 5000

# Команда по умолчанию (переопределяется в docker-compose)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "run:app"]