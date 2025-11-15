#!/bin/bash

# Тестирование DNS-сервера
echo "=== Тестирование DNS-сервера ==="

# Установка адреса DNS-сервера
DNS_SERVER="127.0.0.1"
DNS_PORT="5053"

# Функция для выполнения теста
test_dns_query() {
    local domain=$1
    local qtype=${2:-A}
    local name=${3:-"Тест"}

    echo "=== $name: $domain ($qtype) ==="
    dig @$DNS_SERVER -p $DNS_PORT $domain $qtype +short
    echo ""
}

# Простые тесты
test_dns_query "google.com" "A" "A запись"
test_dns_query "google.com" "AAAA" "AAAA запись"
test_dns_query "google.com" "MX" "MX запись"
test_dns_query "google.com" "NS" "NS запись"
test_dns_query "google.com" "TXT" "TXT запись"

# Тесты с подробным выводом
echo "=== Подробный тест google.com ==="
dig @$DNS_SERVER -p $DNS_PORT google.com A +multiline +noall +answer

echo "=== Тест рекурсии ==="
dig @$DNS_SERVER -p $DNS_PORT cnn.com A +short

echo "=== Тест кеширования (два одинаковых запроса) ==="
time dig @$DNS_SERVER -p $DNS_PORT github.com A +short
time dig @$DNS_SERVER -p $DNS_PORT github.com A +short

echo "Тестирование завершено."