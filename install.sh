#!/bin/bash

# --- install.sh ---
#
# Продвинутый установщик для ASTRACAT DNS Resolver.
#
# Этот скрипт выполняет следующие действия:
# 1. Проверяет наличие прав суперпользователя (root).
# 2. Определяет операционную систему и менеджер пакетов.
# 3. Устанавливает необходимые зависимости для сборки (компилятор, Go, библиотеки).
# 4. Загружает и устанавливает корректную версию Go, если она отсутствует.
# 5. Получает корневые ключи DNSSEC с помощью unbound-anchor.
# 6. Собирает приложение из исходного кода.
# 7. Устанавливает бинарный файл в /usr/local/bin.
# 8. Создает и настраивает службу systemd для автоматического запуска.
# 9. Запускает службу и выводит информацию о статусе.

set -e # Прерывать выполнение при любой ошибке

# --- Переменные ---
GO_VERSION="1.24.3"
GO_URL="https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
INSTALL_DIR="/usr/local"
GO_INSTALL_DIR="${INSTALL_DIR}/go"
PROFILE_PATH="/etc/profile.d/go.sh"
APP_NAME="dns-resolver"
APP_USER="dns-resolver"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
APP_INSTALL_DIR="/usr/local/bin"
APP_BINARY_PATH="${APP_INSTALL_DIR}/${APP_NAME}"
UNBOUND_ROOT_KEY="/etc/unbound/root.key"

# --- Функции ---

# Вывод информационных сообщений
info() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

# Вывод сообщений об ошибках
error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
    exit 1
}

# Проверка на запуск от имени root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "Этот скрипт должен быть запущен с правами суперпользователя (root)."
    fi
}

# Определение ОС и менеджера пакетов
detect_os() {
    info "Определение операционной системы..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        error "Не удалось определить операционную систему."
    fi

    case $OS in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            UPDATE_CMD="$PKG_MANAGER update"
            INSTALL_CMD="$PKG_MANAGER install -y"
            BUILD_DEPS="build-essential gcc curl tar libunbound-dev liblmdb-dev"
            ;;
        centos|rhel|fedora)
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            elif command -v yum &>/dev/null; then
                PKG_MANAGER="yum"
            else
                error "Не найден менеджер пакетов (yum/dnf)."
            fi
            INSTALL_CMD="$PKG_MANAGER install -y"
            BUILD_DEPS="gcc make curl tar unbound-devel lmdb-devel"
            # Для CentOS/RHEL 7 может потребоваться 'yum groupinstall "Development Tools"'
            if [[ "$OS" == "centos" || "$OS" == "rhel" ]]; then
                # Проверяем, доступна ли группа пакетов "Development Tools"
                if yum groupinfo "Development Tools" >/dev/null 2>&1; then
                    info "На системах RHEL/CentOS требуется группа пакетов 'Development Tools'."
                    # Устанавливаем группу пакетов отдельно
                    yum groupinstall -y "Development Tools"
                fi
                # Обновляем список зависимостей, чтобы включить gcc-c++
                BUILD_DEPS="gcc gcc-c++ make curl tar unbound-devel lmdb-devel"
            fi
            ;;
        alpine)
            PKG_MANAGER="apk"
            UPDATE_CMD="$PKG_MANAGER update"
            INSTALL_CMD="$PKG_MANAGER add"
            BUILD_DEPS="build-base gcc curl tar unbound-dev lmdb-dev"
            ;;
        arch)
            PKG_MANAGER="pacman"
            INSTALL_CMD="$PKG_MANAGER -Syu --noconfirm"
            BUILD_DEPS="base-devel gcc curl tar unbound lmdb"
            ;;
        *)
            error "Ваша операционная система ($OS) не поддерживается этим скриптом."
            ;;
    esac
    info "ОС: $OS, Менеджер пакетов: $PKG_MANAGER"
}

# Установка зависимостей
install_dependencies() {
    info "Установка зависимостей..."
    if [ -n "$UPDATE_CMD" ]; then
        $UPDATE_CMD
    fi
    $INSTALL_CMD $BUILD_DEPS
}

# Установка Go
install_go() {
    info "Проверка установки Go..."
    if command -v go &>/dev/null && [[ "$(go version)" == *"$GO_VERSION"* ]]; then
        info "Go $GO_VERSION уже установлен."
        return
    fi

    info "Установка Go $GO_VERSION..."
    if [ -d "$GO_INSTALL_DIR" ]; then
        info "Обнаружена предыдущая версия Go. Удаление..."
        rm -rf "$GO_INSTALL_DIR"
    fi

    curl -L -o "/tmp/go.tar.gz" "$GO_URL"
    tar -C "$INSTALL_DIR" -xzf "/tmp/go.tar.gz"
    rm "/tmp/go.tar.gz"

    info "Настройка переменной окружения PATH..."
    echo "export PATH=\$PATH:${GO_INSTALL_DIR}/bin" > "$PROFILE_PATH"
    export PATH=$PATH:${GO_INSTALL_DIR}/bin
    info "Go $GO_VERSION успешно установлен."
}

# Сборка приложения
build_app() {
    info "Сборка приложения ${APP_NAME}..."
    if ! command -v go &>/dev/null; then
        error "Go не найден в PATH. Убедитесь, что Go установлен корректно."
    fi
    go build -o $APP_NAME -tags="unbound cgo" -ldflags "-s -w" .
    info "Сборка завершена."
}

# Установка приложения
install_app() {
    info "Установка ${APP_NAME}..."
    mv $APP_NAME "$APP_BINARY_PATH"
    chmod +x "$APP_BINARY_PATH"
    info "${APP_NAME} установлен в ${APP_BINARY_PATH}"
}

# Настройка DNSSEC
setup_dnssec() {
    info "Получение корневых ключей DNSSEC..."
    mkdir -p /etc/unbound
    unbound-anchor -a "$UNBOUND_ROOT_KEY" || {
        error "Не удалось получить корневые ключи DNSSEC с помощью unbound-anchor.
Это может быть связано с проблемами сети или отсутствием доступа к корневым серверам.
Убедитесь, что у вас есть доступ в Интернет и попробуйте запустить скрипт еще раз.
Если проблема не устранена, проверьте настройки вашего файрвола или обратитесь к системному администратору."
    }
    info "Ключи DNSSEC успешно настроены."
}


# Создание пользователя и службы systemd
setup_systemd() {
    info "Настройка службы systemd..."

    if ! id -u $APP_USER &>/dev/null; then
        info "Создание пользователя ${APP_USER}..."
        useradd -r -s /bin/false $APP_USER
    fi

    info "Создание файла службы: ${SERVICE_FILE}"
    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=ASTRACAT DNS Resolver
After=network.target
Wants=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
ExecStart=${APP_BINARY_PATH}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
Environment="GOMAXPROCS=1"

[Install]
WantedBy=multi-user.target
EOF

    info "Перезагрузка демона systemd и запуск службы..."
    systemctl daemon-reload
    systemctl enable "$APP_NAME"
    systemctl start "$APP_NAME"
}


# --- Основной скрипт ---
main() {
    check_root
    detect_os
    install_dependencies
    install_go
    setup_dnssec
    build_app
    install_app
    setup_systemd

    info "--------------------------------------------------"
    info "Установка ASTRACAT DNS Resolver успешно завершена!"
    info "--------------------------------------------------"
    info "Служба запущена. Проверить статус можно командой:"
    info "sudo systemctl status ${APP_NAME}"
    info " "
    info "Для просмотра логов используйте команду:"
    info "sudo journalctl -u ${APP_NAME} -f"
    info "--------------------------------------------------"
}

main
