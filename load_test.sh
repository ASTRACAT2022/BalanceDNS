#!/bin/bash

# Нагрузочное тестирование DNS-сервера
echo "=== Нагрузочное тестирование DNS-сервера ==="

DNS_SERVER="127.0.0.1"
DNS_PORT="5053"

# Создание списка доменов для тестирования
cat > domains.txt << EOF
google.com
github.com
stackoverflow.com
amazon.com
wikipedia.org
youtube.com
facebook.com
twitter.com
instagram.com
reddit.com
linkedin.com
yahoo.com
bing.com
apple.com
microsoft.com
netflix.com
amazonaws.com
cloudflare.com
akamai.com
fastly.com
EOF

# Функция для выполнения одного запроса
single_query() {
    local domain=$1
    dig @$DNS_SERVER -p $DNS_PORT $domain A +short > /dev/null 2>&1
    echo $?
}

# Параллельное выполнение запросов
echo "Запуск нагрузочного теста..."

# Количество параллельных потоков
THREADS=${1:-10}
REQUESTS_PER_THREAD=${2:-10}

echo "Потоков: $THREADS, запросов на поток: $REQUESTS_PER_THREAD"

# Запуск теста
time (
    for i in $(seq 1 $THREADS); do
    {
        for j in $(seq 1 $REQUESTS_PER_THREAD); do
        {
            # Случайный выбор домена из списка
            domain=$(shuf -n 1 domains.txt)
            dig @$DNS_SERVER -p $DNS_PORT $domain A +short > /dev/null 2>&1
        }
        done
    } &
    done
    wait
)

echo "Тест завершен."