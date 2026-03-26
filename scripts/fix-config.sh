#!/bin/bash
# fix-config.sh - Скрипт для исправления конфигурации astracat-dns после обновления с DNS-кэшем
# Запускать от root: sudo bash scripts/fix-config.sh

set -e

CONFIG_FILE="/opt/AstracatDNS/config/astracat-dns.toml"
BACKUP_FILE="/opt/AstracatDNS/config/astracat-dns.toml.bak"

echo "=== Скрипт исправления конфигурации astracat-dns ==="

# Проверка существования конфига
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Конфигурационный файл не найден: $CONFIG_FILE"
    exit 1
fi

echo "✓ Найден конфиг: $CONFIG_FILE"

# Создание резервной копии
echo "📋 Создание резервной копии..."
cp "$CONFIG_FILE" "$BACKUP_FILE"
echo "✓ Резервная копия: $BACKUP_FILE"

# Проверка на дубликаты [cache]
CACHE_COUNT=$(grep -c "^\[cache\]" "$CONFIG_FILE" 2>/dev/null || echo "0")
echo "📊 Найдено секций [cache]: $CACHE_COUNT"

if [ "$CACHE_COUNT" -gt 1 ]; then
    echo "⚠️  Обнаружены дубликаты секции [cache]"
    
    # Временный файл для обработки
    TEMP_FILE=$(mktemp)
    
    # Удаляем все секции [cache] и их содержимое
    awk '
    /^\[cache\]/ { 
        skip = 1
        next 
    }
    /^\[/ && skip { 
        skip = 0 
    }
    skip && /^(enabled|max_size|ttl_seconds)/ { 
        next 
    }
    !skip { 
        print 
    }
    ' "$CONFIG_FILE" > "$TEMP_FILE"
    
    # Добавляем правильную секцию [cache] после [server]
    awk '
    /^\[server\]/ { 
        print
        print ""
        print "[cache]"
        print "enabled = true"
        print "max_size = 10000"
        print "ttl_seconds = 300"
        next
    }
    { print }
    ' "$TEMP_FILE" > "$CONFIG_FILE"
    
    rm -f "$TEMP_FILE"
    echo "✓ Дубликаты удалены, добавлена корректная секция [cache]"
fi

# Проверка на отступы в [cache]
if grep -q "^ \+\[cache\]" "$CONFIG_FILE"; then
    echo "⚠️  Обнаружены отступы в секции [cache]"
    
    # Убираем отступы у [cache] и его параметров
    sed -i 's/^ \+\[cache\]/[cache]/' "$CONFIG_FILE"
    sed -i 's/^ \+enabled =/enabled =/' "$CONFIG_FILE"
    sed -i 's/^ \+max_size =/max_size =/' "$CONFIG_FILE"
    sed -i 's/^ \+ttl_seconds =/ttl_seconds =/' "$CONFIG_FILE"
    
    echo "✓ Отступы удалены"
fi

# Финальная проверка
echo ""
echo "📄 Итоговая конфигурация:"
echo "---"
grep -A 4 "^\[cache\]" "$CONFIG_FILE" || echo "[cache] секция не найдена"
echo "---"
echo ""

# Проверка валидности TOML (если есть python)
if command -v python3 &> /dev/null; then
    echo "🔍 Проверка валидности TOML..."
    if python3 -c "import tomllib; tomllib.load(open('$CONFIG_FILE', 'rb'))" 2>/dev/null; then
        echo "✓ TOML валиден"
    else
        echo "⚠️  Возможны проблемы с TOML (проверьте вручную)"
    fi
fi

# Перезапуск сервиса
echo ""
echo "🔄 Перезапуск сервиса astracat-dns..."
sudo systemctl daemon-reload
sudo systemctl restart astracat-dns || {
    echo "❌ Не удалось запустить сервис"
    sudo systemctl status astracat-dns --no-pager
    exit 1
}

sleep 2

# Проверка статуса
echo ""
echo "📊 Статус сервиса:"
sudo systemctl is-active astracat-dns && echo "✓ Сервис запущен" || echo "❌ Сервис не активен"

# Проверка метрик кэша
echo ""
echo "📈 Метрики кэша:"
sleep 1
curl -s http://127.0.0.1:9100/metrics 2>/dev/null | grep dns_cache || echo "⚠️  Метрики недоступны"

echo ""
echo "=== Готово! ==="
echo "Резервная копия старого конфига: $BACKUP_FILE"
