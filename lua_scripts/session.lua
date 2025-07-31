-- session.lua - Управление сессиями удаленного доступа

local session = {}
local config = require("config")

-- Константы
local SESSION_TIMEOUT = 3600 -- 1 час
local HEARTBEAT_INTERVAL = 60 -- 1 минута

-- Статусы сессий
session.STATUS = {
    PENDING = "pending",
    ACTIVE = "active",
    EXPIRED = "expired",
    TERMINATED = "terminated",
    SUSPENDED = "suspended"
}

-- Типы сессий
session.TYPES = {
    FULL_ACCESS = "full_access",
    VIEW_ONLY = "view_only",
    FILE_TRANSFER = "file_transfer",
    COMMAND_ONLY = "command_only",
    CUSTOM = "custom"
}

-- Создание новой сессии
function session.create(session_id, client_id, host_id, permissions, session_type)
    local new_session = {
        session_id = session_id,
        client_id = client_id,
        host_id = host_id,
        permissions = permissions or "full",
        session_type = session_type or session.TYPES.FULL_ACCESS,
        status = session.STATUS.ACTIVE,
        created_at = os.time(),
        last_activity = os.time(),
        expires_at = os.time() + SESSION_TIMEOUT,
        command_count = 0,
        data_transferred = 0,
        command_timestamps = {},
        encryption_key = nil,
        client_info = {},
        host_info = {},
        restrictions = {
            max_commands_per_minute = 60,
            max_data_per_session = 1024 * 1024 * 100, -- 100MB
            allowed_commands = {},
            blocked_commands = {},
            file_access_paths = {},
            network_access = false,
            system_commands = false
        },
        statistics = {
            bytes_sent = 0,
            bytes_received = 0,
            files_transferred = 0,
            commands_executed = 0,
            errors_count = 0,
            last_error = nil
        }
    }
    
    -- Применение настроек из конфигурации
    if config then
        local session_config = config.get_setting("session")
        if session_config then
            new_session.expires_at = os.time() + (session_config.default_timeout or SESSION_TIMEOUT)
        end
    end
    
    print("Session created: " .. session_id .. " (Type: " .. new_session.session_type .. ")")
    return new_session
end

-- Проверка активности сессии
function session.is_active(session_obj)
    if not session_obj then
        return false
    end
    
    local current_time = os.time()
    
    -- Проверка статуса
    if session_obj.status ~= session.STATUS.ACTIVE then
        return false
    end
    
    -- Проверка истечения времени
    if current_time > session_obj.expires_at then
        session_obj.status = session.STATUS.EXPIRED
        return false
    end
    
    -- Проверка последней активности
    if current_time - session_obj.last_activity > HEARTBEAT_INTERVAL * 3 then
        session_obj.status = session.STATUS.EXPIRED
        return false
    end
    
    return true
end

-- Обновление активности сессии
function session.update_activity(session_obj)
    if not session_obj then
        return false
    end
    
    session_obj.last_activity = os.time()
    
    -- Продление времени жизни сессии
    if session_obj.status == session.STATUS.ACTIVE then
        session_obj.expires_at = os.time() + SESSION_TIMEOUT
    end
    
    return true
end

-- Завершение сессии
function session.terminate(session_obj, reason)
    if not session_obj then
        return false
    end
    
    session_obj.status = session.STATUS.TERMINATED
    session_obj.last_activity = os.time()
    session_obj.termination_reason = reason or "Manual termination"
    
    -- Очистка encryption key
    if session_obj.encryption_key then
        session_obj.encryption_key = nil
    end
    
    print("Session terminated: " .. session_obj.session_id .. " (Reason: " .. session_obj.termination_reason .. ")")
    return true
end

-- Приостановка сессии
function session.suspend(session_obj, reason)
    if not session_obj then
        return false
    end
    
    session_obj.status = session.STATUS.SUSPENDED
    session_obj.last_activity = os.time()
    session_obj.suspension_reason = reason or "Manual suspension"
    
    print("Session suspended: " .. session_obj.session_id .. " (Reason: " .. session_obj.suspension_reason .. ")")
    return true
end

-- Возобновление сессии
function session.resume(session_obj)
    if not session_obj then
        return false
    end
    
    if session_obj.status == session.STATUS.SUSPENDED then
        session_obj.status = session.STATUS.ACTIVE
        session_obj.last_activity = os.time()
        session_obj.expires_at = os.time() + SESSION_TIMEOUT
        session_obj.suspension_reason = nil
        
        print("Session resumed: " .. session_obj.session_id)
        return true
    end
    
    return false
end

-- Проверка разрешений
function session.has_permission(session_obj, permission)
    if not session_obj then
        return false
    end
    
    -- Проверка активности сессии
    if not session.is_active(session_obj) then
        return false
    end
    
    -- Полные разрешения
    if session_obj.permissions == "full" then
        return true
    end
    
    -- Проверка конкретного разрешения
    if type(session_obj.permissions) == "table" then
        for _, perm in ipairs(session_obj.permissions) do
            if perm == permission then
                return true
            end
        end
    elseif type(session_obj.permissions) == "string" then
        return session_obj.permissions:find(permission) ~= nil
    end
    
    return false
end

-- Проверка ограничений команд
function session.check_command_limits(session_obj, command)
    if not session_obj then
        return false, "Invalid session"
    end
    
    -- Проверка активности
    if not session.is_active(session_obj) then
        return false, "Session not active"
    end
    
    -- Проверка заблокированных команд
    if session_obj.restrictions.blocked_commands then
        for _, blocked_cmd in ipairs(session_obj.restrictions.blocked_commands) do
            if command:find(blocked_cmd) then
                return false, "Command blocked: " .. blocked_cmd
            end
        end
    end
    
    -- Проверка разрешенных команд (если список не пустой)
    if session_obj.restrictions.allowed_commands and 
       #session_obj.restrictions.allowed_commands > 0 then
        local allowed = false
        for _, allowed_cmd in ipairs(session_obj.restrictions.allowed_commands) do
            if command:find(allowed_cmd) then
                allowed = true
                break
            end
        end
        if not allowed then
            return false, "Command not in allowed list"
        end
    end
    
    -- Проверка лимита команд в минуту
    local current_time = os.time()
    
    -- Очистка старых временных меток
    local recent_commands = {}
    for _, timestamp in ipairs(session_obj.command_timestamps) do
        if current_time - timestamp < 60 then
            table.insert(recent_commands, timestamp)
        end
    end
    session_obj.command_timestamps = recent_commands
    
    -- Проверка лимита
    if #session_obj.command_timestamps >= session_obj.restrictions.max_commands_per_minute then
        return false, "Command rate limit exceeded"
    end
    
    -- Проверка системных команд
    if not session_obj.restrictions.system_commands then
        local system_commands = {"sudo", "su", "passwd", "shutdown", "reboot"}
        for _, sys_cmd in ipairs(system_commands) do
            if command:find(sys_cmd) then
                return false, "System commands not allowed"
            end
        end
    end
    
    return true, "OK"
end

-- Регистрация выполнения команды
function session.register_command_execution(session_obj, command, data_size, success, error_msg)
    if not session_obj then
        return false
    end
    
    session_obj.command_count = session_obj.command_count + 1
    session_obj.statistics.commands_executed = session_obj.statistics.commands_executed + 1
    session_obj.data_transferred = session_obj.data_transferred + (data_size or 0)
    
    -- Добавление временной метки
    table.insert(session_obj.command_timestamps, os.time())
    
    -- Обновление статистики
    if success then
        session_obj.statistics.bytes_sent = session_obj.statistics.bytes_sent + (data_size or 0)
    else
        session_obj.statistics.errors_count = session_obj.statistics.errors_count + 1
        session_obj.statistics.last_error = error_msg
    end
    
    -- Обновление активности
    session.update_activity(session_obj)
    
    return true
end

-- Установка ключа шифрования
function session.set_encryption_key(session_obj, key)
    if not session_obj then
        return false
    end
    
    session_obj.encryption_key = key
    return true
end

-- Получение ключа шифрования
function session.get_encryption_key(session_obj)
    if not session_obj then
        return nil
    end
    
    return session_obj.encryption_key
end

-- Добавление информации о клиенте
function session.set_client_info(session_obj, info)
    if not session_obj then
        return false
    end
    
    session_obj.client_info = info or {}
    return true
end

-- Добавление информации о хосте
function session.set_host_info(session_obj, info)
    if not session_obj then
        return false
    end
    
    session_obj.host_info = info or {}
    return true
end

-- Обновление ограничений сессии
function session.update_restrictions(session_obj, restrictions)
    if not session_obj then
        return false
    end
    
    if restrictions then
        for key, value in pairs(restrictions) do
            session_obj.restrictions[key] = value
        end
    end
    
    return true
end

-- Получение оставшегося времени сессии
function session.get_remaining_time(session_obj)
    if not session_obj then
        return 0
    end
    
    local current_time = os.time()
    local remaining = session_obj.expires_at - current_time
    
    return math.max(0, remaining)
end

-- Продление сессии
function session.extend_session(session_obj, additional_time)
    if not session_obj then
        return false
    end
    
    if not session.is_active(session_obj) then
        return false
    end
    
    additional_time = additional_time or SESSION_TIMEOUT
    session_obj.expires_at = session_obj.expires_at + additional_time
    
    print("Session extended: " .. session_obj.session_id .. " (+" .. additional_time .. "s)")
    return true
end

-- Получение статистики сессии
function session.get_statistics(session_obj)
    if not session_obj then
        return nil
    end
    
    local current_time = os.time()
    local duration = current_time - session_obj.created_at
    
    return {
        session_id = session_obj.session_id,
        client_id = session_obj.client_id,
        host_id = session_obj.host_id,
        session_type = session_obj.session_type,
        status = session_obj.status,
        duration = duration,
        remaining_time = session.get_remaining_time(session_obj),
        created_at = session_obj.created_at,
        last_activity = session_obj.last_activity,
        expires_at = session_obj.expires_at,
        command_count = session_obj.command_count,
        data_transferred = session_obj.data_transferred,
        permissions = session_obj.permissions,
        is_active = session.is_active(session_obj),
        statistics = session_obj.statistics,
        client_info = session_obj.client_info,
        host_info = session_obj.host_info,
        termination_reason = session_obj.termination_reason,
        suspension_reason = session_obj.suspension_reason
    }
end

-- Проверка доступа к файлам
function session.check_file_access(session_obj, file_path)
    if not session_obj then
        return false, "Invalid session"
    end
    
    if not session.is_active(session_obj) then
        return false, "Session not active"
    end
    
    -- Если нет ограничений на пути, разрешаем все
    if not session_obj.restrictions.file_access_paths or 
       #session_obj.restrictions.file_access_paths == 0 then
        return true, "OK"
    end
    
    -- Проверка разрешенных путей
    for _, allowed_path in ipairs(session_obj.restrictions.file_access_paths) do
        if file_path:find(allowed_path) == 1 then
            return true, "OK"
        end
    end
    
    return false, "File access denied"
end

-- Регистрация передачи файла
function session.register_file_transfer(session_obj, file_path, file_size, direction)
    if not session_obj then
        return false
    end
    
    session_obj.statistics.files_transferred = session_obj.statistics.files_transferred + 1
    
    if direction == "upload" then
        session_obj.statistics.bytes_received = session_obj.statistics.bytes_received + file_size
    else
        session_obj.statistics.bytes_sent = session_obj.statistics.bytes_sent + file_size
    end
    
    session_obj.data_transferred = session_obj.data_transferred + file_size
    
    -- Обновление активности
    session.update_activity(session_obj)
    
    return true
end

-- Проверка лимитов передачи данных
function session.check_data_limits(session_obj, additional_data)
    if not session_obj then
        return false, "Invalid session"
    end
    
    local total_data = session_obj.data_transferred + additional_data
    
    if total_data > session_obj.restrictions.max_data_per_session then
        return false, "Data transfer limit exceeded"
    end
    
    return true, "OK"
end

-- Получение информации о сессии для отправки
function session.get_session_info(session_obj)
    if not session_obj then
        return nil
    end
    
    return {
        session_id = session_obj.session_id,
        client_id = session_obj.client_id,
        host_id = session_obj.host_id,
        session_type = session_obj.session_type,
        permissions = session_obj.permissions,
        created_at = session_obj.created_at,
        expires_at = session_obj.expires_at,
        status = session_obj.status
    }
end

-- Валидация сессии
function session.validate(session_obj)
    if not session_obj then
        return false, "Session object is nil"
    end
    
    if not session_obj.session_id or session_obj.session_id == "" then
        return false, "Invalid session ID"
    end
    
    if not session_obj.client_id or session_obj.client_id == "" then
        return false, "Invalid client ID"
    end
    
    if not session_obj.host_id or session_obj.host_id == "" then
        return false, "Invalid host ID"
    end
    
    if not session_obj.created_at or session_obj.created_at <= 0 then
        return false, "Invalid creation time"
    end
    
    return true, "Session is valid"
end

-- Клонирование сессии (для создания копии)
function session.clone(session_obj)
    if not session_obj then
        return nil
    end
    
    -- Создаем глубокую копию
    local function deep_copy(obj)
        if type(obj) ~= "table" then
            return obj
        end
        
        local copy = {}
        for key, value in pairs(obj) do
            copy[key] = deep_copy(value)
        end
        
        return copy
    end
    
    return deep_copy(session_obj)
end

-- Экспорт сессии в JSON-подобный формат
function session.export(session_obj)
    if not session_obj then
        return nil
    end
    
    local export_data = {
        session_id = session_obj.session_id,
        client_id = session_obj.client_id,
        host_id = session_obj.host_id,
        permissions = session_obj.permissions,
        session_type = session_obj.session_type,
        status = session_obj.status,
        created_at = session_obj.created_at,
        last_activity = session_obj.last_activity,
        expires_at = session_obj.expires_at,
        command_count = session_obj.command_count,
        data_transferred = session_obj.data_transferred,
        statistics = session_obj.statistics,
        restrictions = session_obj.restrictions,
        client_info = session_obj.client_info,
        host_info = session_obj.host_info,
        termination_reason = session_obj.termination_reason,
        suspension_reason = session_obj.suspension_reason
    }
    
    return export_data
end

-- Импорт сессии из JSON-подобного формата
function session.import(import_data)
    if not import_data or type(import_data) ~= "table" then
        return nil
    end
    
    local session_obj = {
        session_id = import_data.session_id or "",
        client_id = import_data.client_id or "",
        host_id = import_data.host_id or "",
        permissions = import_data.permissions or "full",
        session_type = import_data.session_type or session.TYPES.FULL_ACCESS,
        status = import_data.status or session.STATUS.ACTIVE,
        created_at = import_data.created_at or os.time(),
        last_activity = import_data.last_activity or os.time(),
        expires_at = import_data.expires_at or (os.time() + SESSION_TIMEOUT),
        command_count = import_data.command_count or 0,
        data_transferred = import_data.data_transferred or 0,
        command_timestamps = {},
        encryption_key = nil,
        client_info = import_data.client_info or {},
        host_info = import_data.host_info or {},
        restrictions = import_data.restrictions or {
            max_commands_per_minute = 60,
            max_data_per_session = 1024 * 1024 * 100,
            allowed_commands = {},
            blocked_commands = {},
            file_access_paths = {},
            network_access = false,
            system_commands = false
        },
        statistics = import_data.statistics or {
            bytes_sent = 0,
            bytes_received = 0,
            files_transferred = 0,
            commands_executed = 0,
            errors_count = 0,
            last_error = nil
        },
        termination_reason = import_data.termination_reason,
        suspension_reason = import_data.suspension_reason
    }
    
    return session_obj
end

-- Получение всех активных сессий (для менеджера сессий)
local active_sessions = {}

function session.get_all_active()
    local active = {}
    for session_id, session_obj in pairs(active_sessions) do
        if session.is_active(session_obj) then
            active[session_id] = session_obj
        else
            -- Удаляем неактивные сессии
            active_sessions[session_id] = nil
        end
    end
    return active
end

-- Добавление сессии в глобальный реестр
function session.register_session(session_obj)
    if not session_obj or not session_obj.session_id then
        return false
    end
    
    active_sessions[session_obj.session_id] = session_obj
    print("Session registered: " .. session_obj.session_id)
    return true
end

-- Удаление сессии из глобального реестра
function session.unregister_session(session_id)
    if active_sessions[session_id] then
        active_sessions[session_id] = nil
        print("Session unregistered: " .. session_id)
        return true
    end
    return false
end

-- Поиск сессии по ID
function session.find_by_id(session_id)
    return active_sessions[session_id]
end

-- Поиск сессий по client_id
function session.find_by_client(client_id)
    local client_sessions = {}
    for session_id, session_obj in pairs(active_sessions) do
        if session_obj.client_id == client_id then
            table.insert(client_sessions, session_obj)
        end
    end
    return client_sessions
end

-- Поиск сессий по host_id
function session.find_by_host(host_id)
    local host_sessions = {}
    for session_id, session_obj in pairs(active_sessions) do
        if session_obj.host_id == host_id then
            table.insert(host_sessions, session_obj)
        end
    end
    return host_sessions
end

-- Очистка всех неактивных сессий
function session.cleanup_inactive()
    local cleaned_count = 0
    for session_id, session_obj in pairs(active_sessions) do
        if not session.is_active(session_obj) then
            active_sessions[session_id] = nil
            cleaned_count = cleaned_count + 1
        end
    end
    
    if cleaned_count > 0 then
        print("Cleaned up " .. cleaned_count .. " inactive sessions")
    end
    
    return cleaned_count
end

-- Принудительное завершение всех сессий
function session.terminate_all(reason)
    local terminated_count = 0
    reason = reason or "System shutdown"
    
    for session_id, session_obj in pairs(active_sessions) do
        if session.terminate(session_obj, reason) then
            terminated_count = terminated_count + 1
        end
    end
    
    active_sessions = {}
    print("All sessions terminated: " .. terminated_count)
    return terminated_count
end

-- Получение статистики всех сессий
function session.get_global_statistics()
    local total_sessions = 0
    local active_count = 0
    local total_commands = 0
    local total_data = 0
    local total_files = 0
    
    for session_id, session_obj in pairs(active_sessions) do
        total_sessions = total_sessions + 1
        
        if session.is_active(session_obj) then
            active_count = active_count + 1
        end
        
        total_commands = total_commands + session_obj.command_count
        total_data = total_data + session_obj.data_transferred
        total_files = total_files + session_obj.statistics.files_transferred
    end
    
    return {
        total_sessions = total_sessions,
        active_sessions = active_count,
        inactive_sessions = total_sessions - active_count,
        total_commands_executed = total_commands,
        total_data_transferred = total_data,
        total_files_transferred = total_files,
        session_timeout = SESSION_TIMEOUT,
        heartbeat_interval = HEARTBEAT_INTERVAL
    }
end

-- Создание сессии с автоматической регистрацией
function session.create_and_register(session_id, client_id, host_id, permissions, session_type)
    local new_session = session.create(session_id, client_id, host_id, permissions, session_type)
    if new_session then
        session.register_session(new_session)
    end
    return new_session
end

-- Безопасное завершение сессии с автоматической отрегистрацией
function session.terminate_and_unregister(session_obj, reason)
    if not session_obj then
        return false
    end
    
    local session_id = session_obj.session_id
    local success = session.terminate(session_obj, reason)
    
    if success then
        session.unregister_session(session_id)
    end
    
    return success
end

-- Проверка конфликтов сессий (один клиент - один хост)
function session.check_conflicts(client_id, host_id)
    local conflicts = {}
    
    for session_id, session_obj in pairs(active_sessions) do
        if session.is_active(session_obj) and
           session_obj.client_id == client_id and
           session_obj.host_id == host_id then
            table.insert(conflicts, session_obj)
        end
    end
    
    return conflicts
end

-- Разрешение конфликтов сессий
function session.resolve_conflicts(client_id, host_id, resolution_type)
    local conflicts = session.check_conflicts(client_id, host_id)
    
    if #conflicts == 0 then
        return true, "No conflicts found"
    end
    
    resolution_type = resolution_type or "terminate_old"
    
    if resolution_type == "terminate_old" then
        -- Завершаем все старые сессии
        for _, conflict_session in ipairs(conflicts) do
            session.terminate_and_unregister(conflict_session, "Conflict resolution")
        end
        return true, "Old sessions terminated"
        
    elseif resolution_type == "deny_new" then
        -- Отклоняем новую сессию
        return false, "Active session exists"
        
    elseif resolution_type == "suspend_old" then
        -- Приостанавливаем старые сессии
        for _, conflict_session in ipairs(conflicts) do
            session.suspend(conflict_session, "Conflict resolution")
        end
        return true, "Old sessions suspended"
        
    else
        return false, "Unknown resolution type"
    end
end

-- Восстановление сессии после сбоя
function session.restore_from_backup(backup_data)
    if not backup_data or type(backup_data) ~= "table" then
        return nil
    end
    
    local restored_session = session.import(backup_data)
    if not restored_session then
        return nil
    end
    
    -- Проверяем, не истекла ли сессия
    if restored_session.expires_at <= os.time() then
        restored_session.status = session.STATUS.EXPIRED
        return restored_session
    end
    
    -- Регистрируем восстановленную сессию
    session.register_session(restored_session)
    
    print("Session restored from backup: " .. restored_session.session_id)
    return restored_session
end

-- Создание резервной копии сессии
function session.create_backup(session_obj)
    if not session_obj then
        return nil
    end
    
    local backup = session.export(session_obj)
    backup.backup_created_at = os.time()
    backup.backup_version = "1.0"
    
    return backup
end

-- Периодическая очистка и обслуживание
function session.maintenance()
    local stats = {
        cleaned_sessions = 0,
        active_sessions = 0,
        expired_sessions = 0,
        errors = {}
    }
    
    -- Очистка неактивных сессий
    stats.cleaned_sessions = session.cleanup_inactive()
    
    -- Подсчет статистики
    for session_id, session_obj in pairs(active_sessions) do
        if session.is_active(session_obj) then
            stats.active_sessions = stats.active_sessions + 1
        else
            stats.expired_sessions = stats.expired_sessions + 1
        end
        
        -- Проверка валидности
        local is_valid, error_msg = session.validate(session_obj)
        if not is_valid then
            table.insert(stats.errors, {
                session_id = session_id,
                error = error_msg
            })
        end
    end
    
    print("Session maintenance completed: " .. stats.cleaned_sessions .. " cleaned, " .. 
          stats.active_sessions .. " active, " .. stats.expired_sessions .. " expired")
    
    return stats
end

-- Установка callback'ов для событий сессии
local session_callbacks = {
    on_create = nil,
    on_terminate = nil,
    on_suspend = nil,
    on_resume = nil,
    on_expire = nil,
    on_command_execute = nil
}

function session.set_callback(event, callback)
    if session_callbacks[event] ~= nil then
        session_callbacks[event] = callback
        return true
    end
    return false
end

-- Вызов callback'а
local function call_callback(event, session_obj, ...)
    if session_callbacks[event] then
        session_callbacks[event](session_obj, ...)
    end
end

-- Модификация существующих функций для добавления callback'ов
local original_create = session.create
function session.create(session_id, client_id, host_id, permissions, session_type)
    local new_session = original_create(session_id, client_id, host_id, permissions, session_type)
    call_callback("on_create", new_session)
    return new_session
end

local original_terminate = session.terminate
function session.terminate(session_obj, reason)
    local result = original_terminate(session_obj, reason)
    if result then
        call_callback("on_terminate", session_obj, reason)
    end
    return result
end

local original_suspend = session.suspend
function session.suspend(session_obj, reason)
    local result = original_suspend(session_obj, reason)
    if result then
        call_callback("on_suspend", session_obj, reason)
    end
    return result
end

local original_resume = session.resume
function session.resume(session_obj)
    local result = original_resume(session_obj)
    if result then
        call_callback("on_resume", session_obj)
    end
    return result
end

-- Установка таймеров для автоматической очистки
local cleanup_timer = nil
local maintenance_timer = nil

function session.start_auto_cleanup(interval)
    interval = interval or 300 -- 5 минут по умолчанию
    
    if cleanup_timer then
        -- Останавливаем предыдущий таймер
        session.stop_auto_cleanup()
    end
    
    -- В реальной реализации здесь должен быть настоящий таймер
    -- Для примера используем простую заглушку
    cleanup_timer = {
        interval = interval,
        active = true,
        last_run = os.time()
    }
    
    print("Auto cleanup started with interval: " .. interval .. "s")
    return true
end

function session.stop_auto_cleanup()
    if cleanup_timer then
        cleanup_timer.active = false
        cleanup_timer = nil
        print("Auto cleanup stopped")
        return true
    end
    return false
end

-- Сохранение состояния всех сессий
function session.save_state(filepath)
    local state = {
        sessions = {},
        metadata = {
            saved_at = os.time(),
            version = "1.0",
            total_sessions = 0
        }
    }
    
    for session_id, session_obj in pairs(active_sessions) do
        state.sessions[session_id] = session.export(session_obj)
        state.metadata.total_sessions = state.metadata.total_sessions + 1
    end
    
    -- В реальной реализации здесь должно быть сохранение в файл
    print("Session state saved: " .. state.metadata.total_sessions .. " sessions")
    return state
end

-- Загрузка состояния всех сессий
function session.load_state(state_data)
    if not state_data or not state_data.sessions then
        return false, "Invalid state data"
    end
    
    local loaded_count = 0
    local errors = {}
    
    for session_id, session_data in pairs(state_data.sessions) do
        local restored_session = session.import(session_data)
        if restored_session then
            session.register_session(restored_session)
            loaded_count = loaded_count + 1
        else
            table.insert(errors, "Failed to restore session: " .. session_id)
        end
    end
    
    print("Session state loaded: " .. loaded_count .. " sessions restored")
    
    if #errors > 0 then
        return false, "Some sessions failed to load: " .. table.concat(errors, ", ")
    end
    
    return true, "All sessions loaded successfully"
end

return session