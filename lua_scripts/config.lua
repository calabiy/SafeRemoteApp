-- config.lua - Конфигурация системы удаленного доступа

local config = {}

-- Основные настройки
config.settings = {
    -- Сетевые настройки
    network = {
        default_server_port = 8080,
        connection_timeout = 30,
        heartbeat_interval = 60,
        max_reconnect_attempts = 5,
        reconnect_delay = 5
    },
    
    -- Настройки сессий
    session = {
        default_timeout = 3600, -- 1 час
        max_sessions_per_device = 5,
        auto_approve_trusted = true,
        require_confirmation = true,
        max_idle_time = 1800 -- 30 минут
    },
    
    -- Настройки безопасности
    security = {
        encryption_enabled = true,
        key_exchange_algorithm = "ECDH",
        cipher_algorithm = "AES-256-GCM",
        require_device_verification = true,
        max_failed_attempts = 3,
        lockout_duration = 300 -- 5 минут
    },
    
    -- Настройки уведомлений
    notifications = {
        show_access_requests = true,
        show_session_events = true,
        show_command_execution = false,
        notification_timeout = 30,
        sound_enabled = true,
        vibration_enabled = true
    },
    
    -- Настройки логирования
    logging = {
        enabled = true,
        level = "INFO", -- DEBUG, INFO, WARN, ERROR
        max_log_size = 10 * 1024 * 1024, -- 10MB
        max_log_files = 5,
        log_commands = true,
        log_connections = true
    },
    
    -- Настройки мобильного приложения
    mobile = {
        background_execution = true,
        push_notifications = true,
        auto_start = false,
        battery_optimization = true,
        screen_always_on = false
    }
}

-- Возможности устройства
config.device_capabilities = {
    -- Основные возможности
    basic = {
        "file_transfer",
        "remote_control",
        "screen_sharing",
        "clipboard_sync",
        "notification_relay"
    },
    
    -- Расширенные возможности
    advanced = {
        "system_info",
        "process_management",
        "network_monitoring",
        "hardware_control",
        "automation"
    },
    
    -- Мобильные возможности
    mobile = {
        "camera_access",
        "location_sharing",
        "sensor_data",
        "call_management",
        "sms_relay"
    }
}

-- Разрешения по умолчанию
config.default_permissions = {
    guest = {
        "view_screen",
        "basic_commands"
    },
    
    user = {
        "view_screen",
        "basic_commands",
        "file_transfer",
        "clipboard_sync"
    },
    
    admin = {
        "view_screen",
        "basic_commands",
        "file_transfer",
        "clipboard_sync",
        "system_control",
        "process_management"
    },
    
    full = {
        "view_screen",
        "basic_commands",
        "file_transfer",
        "clipboard_sync",
        "system_control",
        "process_management",
        "hardware_control",
        "network_access",
        "automation"
    }
}

-- Разрешенные команды
config.allowed_commands = {
    -- Базовые команды
    basic = {
        "echo",
        "date",
        "whoami",
        "pwd",
        "ls",
        "dir",
        "cat",
        "type",
        "ping"
    },
    
    -- Системные команды
    system = {
        "ps",
        "top",
        "htop",
        "df",
        "du",
        "free",
        "uptime",
        "uname",
        "systemctl",
        "service"
    },
    
    -- Файловые операции
    file = {
        "cp",
        "mv",
        "rm",
        "mkdir",
        "rmdir",
        "chmod",
        "chown",
        "find",
        "locate"
    },
    
    -- Сетевые команды
    network = {
        "netstat",
        "ss",
        "lsof",
        "iptables",
        "route",
        "ifconfig",
        "ip"
    }
}

-- Заблокированные команды
config.blocked_commands = {
    "rm -rf /",
    "format",
    "fdisk",
    "mkfs",
    "dd",
    "shutdown",
    "reboot",
    "halt",
    "passwd",
    "su",
    "sudo",
    "chmod 777",
    "chown root"
}

-- Предустановленные команды
config.command_presets = {
    system_info = {
        name = "System Information",
        description = "Get basic system information",
        command = "uname -a && free -h && df -h",
        args = {},
        permissions_required = {"system_info"}
    },
    
    process_list = {
        name = "Process List",
        description = "Show running processes",
        command = "ps aux",
        args = {},
        permissions_required = {"process_management"}
    },
    
    network_status = {
        name = "Network Status",
        description = "Show network connections",
        command = "netstat -tulpn",
        args = {},
        permissions_required = {"network_access"}
    },
    
    disk_usage = {
        name = "Disk Usage",
        description = "Show disk usage information",
        command = "df -h && du -sh /*",
        args = {},
        permissions_required = {"system_info"}
    },
    
    screenshot = {
        name = "Take Screenshot",
        description = "Capture screen screenshot",
        command = "screenshot",
        args = {format = "png", quality = 80},
        permissions_required = {"view_screen"}
    }
}

-- Настройки шифрования
config.encryption = {
    key_size = 256,
    iv_size = 16,
    salt_size = 32,
    pbkdf2_iterations = 100000,
    signature_algorithm = "ECDSA"
}

-- Настройки для разных платформ
config.platform_settings = {
    android = {
        service_name = "SafeRemoteService",
        notification_channel = "remote_access",
        wake_lock_enabled = true,
        foreground_service = true
    },
    
    ios = {
        background_app_refresh = true,
        push_notifications = true,
        keychain_access = true
    },
    
    desktop = {
        system_tray = true,
        auto_start = false,
        minimize_to_tray = true
    }
}

-- Получение настроек
function config.get_setting(path)
    local keys = {}
    for key in path:gmatch("[^.]+") do
        table.insert(keys, key)
    end
    
    local value = config.settings
    for _, key in ipairs(keys) do
        if type(value) == "table" and value[key] then
            value = value[key]
        else
            return nil
        end
    end
    
    return value
end

-- Установка настроек
function config.set_setting(path, value)
    local keys = {}
    for key in path:gmatch("[^.]+") do
        table.insert(keys, key)
    end
    
    local current = config.settings
    for i = 1, #keys - 1 do
        local key = keys[i]
        if type(current[key]) ~= "table" then
            current[key] = {}
        end
        current = current[key]
    end
    
    current[keys[#keys]] = value
    return true
end

-- Получение возможностей устройства
function config.get_capabilities()
    local capabilities = {}
    
    -- Объединение всех возможностей
    for category, caps in pairs(config.device_capabilities) do
        for _, cap in ipairs(caps) do
            table.insert(capabilities, cap)
        end
    end
    
    return capabilities
end

-- Получение разрешений по типу
function config.get_permissions(permission_type)
    return config.default_permissions[permission_type] or {}
end

-- Проверка разрешенности команды
function config.is_command_allowed(command)
    -- Проверка в заблокированных командах
    for _, blocked in ipairs(config.blocked_commands) do
        if command:find(blocked) then
            return false
        end
    end
    
    -- Проверка в разрешенных командах
    for category, commands in pairs(config.allowed_commands) do
        for _, allowed in ipairs(commands) do
            if command:find(allowed) then
                return true
            end
        end
    end
    
    return false
end

-- Получение предустановленных команд
function config.get_command_presets()
    return config.command_presets
end

-- Проверка разрешения для команды
function config.check_command_permission(command, user_permissions)
    -- Поиск команды в предустановленных
    for preset_name, preset in pairs(config.command_presets) do
        if preset.command:find(command) then
            -- Проверка разрешений
            for _, required_perm in ipairs(preset.permissions_required) do
                local has_permission = false
                for _, user_perm in ipairs(user_permissions) do
                    if user_perm == required_perm then
                        has_permission = true
                        break
                    end
                end
                if not has_permission then
                    return false, "Permission denied: " .. required_perm
                end
            end
            return true
        end
    end
    
    -- Если команда не найдена в предустановленных, проверяем базовые разрешения
    return config.is_command_allowed(command), "Command not allowed"
end

-- Загрузка конфигурации из файла
function config.load_from_file(filename)
    -- В реальной реализации здесь должна быть загрузка из файла
    print("Loading config from: " .. filename)
    return true
end

-- Сохранение конфигурации в файл
function config.save_to_file(filename)
    -- В реальной реализации здесь должно быть сохранение в файл
    print("Saving config to: " .. filename)
    return true
end

-- Получение конфигурации для платформы
function config.get_platform_config()
    local platform = "desktop" -- По умолчанию
    
    -- Определение платформы (в реальной реализации через cpp_bridge)
    if cpp_bridge then
        platform = cpp_bridge.get_platform()
    end
    
    return config.platform_settings[platform] or config.platform_settings.desktop
end

-- Валидация конфигурации
function config.validate()
    local errors = {}
    
    -- Проверка сетевых настроек
    if config.settings.network.default_server_port < 1 or 
       config.settings.network.default_server_port > 65535 then
        table.insert(errors, "Invalid server port")
    end
    
    -- Проверка таймаутов
    if config.settings.session.default_timeout < 60 then
        table.insert(errors, "Session timeout too short")
    end
    
    -- Проверка алгоритмов шифрования
    local valid_ciphers = {"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305"}
    local cipher_valid = false
    for _, cipher in ipairs(valid_ciphers) do
        if cipher == config.settings.security.cipher_algorithm then
            cipher_valid = true
            break
        end
    end
    if not cipher_valid then
        table.insert(errors, "Invalid cipher algorithm")
    end
    
    return #errors == 0, errors
end

-- Сброс настроек к значениям по умолчанию
function config.reset_to_defaults()
    -- Здесь должна быть логика сброса
    print("Configuration reset to defaults")
    return true
end

-- Получение версии конфигурации
function config.get_version()
    return "1.0.0"
end

return config