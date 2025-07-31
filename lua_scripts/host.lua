-- host.lua - Логика хоста (получатель запросов)

local host = {}
local config = require("config")
local session = require("session")

-- Состояние хоста
host.state = {
    device_id = "",
    device_name = "",
    listening = false,
    pending_requests = {},
    active_sessions = {},
    command_history = {}
}

-- Инициализация хоста
function host.init(device_id, device_name)
    host.state.device_id = device_id
    host.state.device_name = device_name
    
    print("Host initialized: " .. device_name .. " (" .. device_id .. ")")
    
    -- Регистрация устройства в системе авторизации
    if cpp_bridge then
        cpp_bridge.register_device(device_id, device_name, host.get_public_key())
    end
    
    return true
end

-- Начало прослушивания запросов
function host.start_listening()
    host.state.listening = true
    print("Host started listening for requests")
    
    -- Установка callback'а для входящих сообщений
    if cpp_bridge then
        cpp_bridge.set_message_callback(host.handle_message)
    end
    
    return true
end

-- Остановка прослушивания
function host.stop_listening()
    host.state.listening = false
    print("Host stopped listening")
    
    -- Завершение всех активных сессий
    for session_id, _ in pairs(host.state.active_sessions) do
        host.terminate_session(session_id)
    end
    
    return true
end

-- Обработка входящих сообщений
function host.handle_message(message)
    if not host.state.listening then
        return
    end
    
    local msg_type = message.type
    local sender_id = message.sender_id
    local session_id = message.session_id
    local data = message.data
    
    print("Received message type: " .. msg_type .. " from: " .. sender_id)
    
    if msg_type == "ACCESS_REQUEST" then
        host.handle_access_request(message)
    elseif msg_type == "COMMAND_EXECUTE" then
        host.handle_command_execute(message)
    elseif msg_type == "SESSION_HEARTBEAT" then
        host.handle_session_heartbeat(message)
    elseif msg_type == "SESSION_END" then
        host.handle_session_end(message)
    else
        print("Unknown message type: " .. msg_type)
    end
end

-- Обработка запроса на доступ
function host.handle_access_request(message)
    local request_data = host.parse_json(message.data)
    if not request_data then
        print("Invalid access request data")
        return
    end
    
    local request = {
        request_id = message.session_id,
        sender_id = message.sender_id,
        sender_name = request_data.sender_name or "Unknown Device",
        permissions = request_data.permissions or "full",
        timestamp = os.time(),
        status = "pending"
    }
    
    host.state.pending_requests[request.request_id] = request
    
    print("Access request from: " .. request.sender_name .. " (" .. request.sender_id .. ")")
    
    -- Проверка доверенности устройства
    if cpp_bridge and cpp_bridge.is_device_trusted(request.sender_id) then
        print("Device is trusted, auto-approving")
        host.approve_request(request.request_id)
    else
        -- Отправка уведомления пользователю
        host.notify_user_about_request(request)
    end
end

-- Уведомление пользователя о запросе
function host.notify_user_about_request(request)
    if cpp_bridge then
        local notification = {
            title = "Remote Access Request",
            message = request.sender_name .. " wants to access your device",
            actions = {"Approve", "Deny"},
            request_id = request.request_id
        }
        
        cpp_bridge.show_notification(host.to_json(notification))
    end
end

-- Одобрение запроса
function host.approve_request(request_id)
    local request = host.state.pending_requests[request_id]
    if not request then
        print("Request not found: " .. request_id)
        return false
    end
    
    request.status = "approved"
    
    -- Создание сессии через C++
    local session_id = request_id
    if cpp_bridge then
        cpp_bridge.authorize_session(session_id, true)
    end
    
    -- Создание локальной сессии
    local new_session = session.create(session_id, request.sender_id, host.state.device_id, request.permissions)
    host.state.active_sessions[session_id] = new_session
    
    -- Отправка ответа клиенту
    local response = {
        type = "ACCESS_RESPONSE",
        sender_id = host.state.device_id,
        receiver_id = request.sender_id,
        session_id = session_id,
        data = host.to_json({
            approved = true,
            session_id = session_id,
            permissions = request.permissions,
            host_info = {
                name = host.state.device_name,
                capabilities = config.get_capabilities()
            }
        }),
        timestamp = os.time()
    }
    
    if cpp_bridge then
        cpp_bridge.send_message(host.to_json(response))
    end
    
    print("Access approved for session: " .. session_id)
    return true
end

-- Отклонение запроса
function host.deny_request(request_id)
    local request = host.state.pending_requests[request_id]
    if not request then
        print("Request not found: " .. request_id)
        return false
    end
    
    request.status = "denied"
    
    -- Отправка отказа клиенту
    local response = {
        type = "ACCESS_RESPONSE",
        sender_id = host.state.device_id,
        receiver_id = request.sender_id,
        session_id = request_id,
        data = host.to_json({
            approved = false,
            reason = "Access denied by user"
        }),
        timestamp = os.time()
    }
    
    if cpp_bridge then
        cpp_bridge.send_message(host.to_json(response))
    end
    
    print("Access denied for request: " .. request_id)
    return true
end

-- Обработка выполнения команды
function host.handle_command_execute(message)
    local session_id = message.session_id
    local active_session = host.state.active_sessions[session_id]
    
    if not active_session then
        print("Session not found: " .. session_id)
        return
    end
    
    if not session.is_active(active_session) then
        print("Session is not active: " .. session_id)
        return
    end
    
    local command_data = host.parse_json(message.data)
    if not command_data then
        print("Invalid command data")
        return
    end
    
    local command = command_data.command
    local args = command_data.args or {}
    
    print("Executing command: " .. command)
    
    -- Проверка разрешений
    if not session.has_permission(active_session, "execute") then
        host.send_command_result(session_id, message.sender_id, {
            success = false,
            error = "Permission denied",
            command = command
        })
        return
    end
    
    -- Проверка разрешенных команд
    if not config.is_command_allowed(command) then
        host.send_command_result(session_id, message.sender_id, {
            success = false,
            error = "Command not allowed",
            command = command
        })
        return
    end
    
    -- Выполнение команды через C++
    local result = {}
    if cpp_bridge then
        result = cpp_bridge.execute_command(command, host.to_json(args))
    else
        -- Fallback для тестирования
        result = {
            success = true,
            output = "Command executed: " .. command,
            exit_code = 0
        }
    end
    
    -- Запись в историю
    local history_entry = {
        session_id = session_id,
        command = command,
        args = args,
        result = result,
        timestamp = os.time()
    }
    table.insert(host.state.command_history, history_entry)
    
    -- Отправка результата
    host.send_command_result(session_id, message.sender_id, result)
    
    -- Обновление активности сессии
    session.update_activity(active_session)
end

-- Отправка результата команды
function host.send_command_result(session_id, receiver_id, result)
    local response = {
        type = "COMMAND_RESULT",
        sender_id = host.state.device_id,
        receiver_id = receiver_id,
        session_id = session_id,
        data = host.to_json(result),
        timestamp = os.time()
    }
    
    if cpp_bridge then
        cpp_bridge.send_message(host.to_json(response))
    end
end

-- Обработка heartbeat сессии
function host.handle_session_heartbeat(message)
    local session_id = message.session_id
    local active_session = host.state.active_sessions[session_id]
    
    if active_session then
        session.update_activity(active_session)
        print("Session heartbeat: " .. session_id)
    end
end

-- Обработка завершения сессии
function host.handle_session_end(message)
    local session_id = message.session_id
    host.terminate_session(session_id)
end

-- Завершение сессии
function host.terminate_session(session_id)
    local active_session = host.state.active_sessions[session_id]
    if active_session then
        session.terminate(active_session)
        host.state.active_sessions[session_id] = nil
        
        -- Уведомление C++ об окончании сессии
        if cpp_bridge then
            cpp_bridge.terminate_session(session_id)
        end
        
        print("Session terminated: " .. session_id)
    end
end

-- Получение списка активных сессий
function host.get_active_sessions()
    local sessions = {}
    for session_id, session_data in pairs(host.state.active_sessions) do
        if session.is_active(session_data) then
            table.insert(sessions, {
                session_id = session_id,
                client_id = session_data.client_id,
                permissions = session_data.permissions,
                created_at = session_data.created_at,
                last_activity = session_data.last_activity
            })
        end
    end
    return sessions
end

-- Получение истории команд
function host.get_command_history(limit)
    limit = limit or 100
    local history = {}
    local count = 0
    
    for i = #host.state.command_history, 1, -1 do
        if count >= limit then break end
        table.insert(history, host.state.command_history[i])
        count = count + 1
    end
    
    return history
end

-- Очистка неактивных сессий
function host.cleanup_sessions()
    local current_time = os.time()
    local cleaned = 0
    
    for session_id, session_data in pairs(host.state.active_sessions) do
        if not session.is_active(session_data) then
            host.state.active_sessions[session_id] = nil
            cleaned = cleaned + 1
        end
    end
    
    print("Cleaned up " .. cleaned .. " inactive sessions")
    return cleaned
end

-- Получение публичного ключа устройства
function host.get_public_key()
    -- В реальной реализации должен возвращать настоящий публичный ключ
    return "HOST_PUBLIC_KEY_" .. host.state.device_id
end

-- Получение статуса хоста
function host.get_status()
    return {
        device_id = host.state.device_id,
        device_name = host.state.device_name,
        listening = host.state.listening,
        active_sessions = #host.get_active_sessions(),
        pending_requests = #host.state.pending_requests,
        total_commands = #host.state.command_history
    }
end

-- Утилиты для работы с JSON
function host.to_json(data)
    if type(data) == "table" then
        local result = "{"
        local first = true
        for k, v in pairs(data) do
            if not first then result = result .. "," end
            result = result .. '"' .. k .. '":' .. host.to_json(v)
            first = false
        end
        return result .. "}"
    elseif type(data) == "string" then
        return '"' .. data .. '"'
    elseif type(data) == "number" then
        return tostring(data)
    elseif type(data) == "boolean" then
        return data and "true" or "false"
    else
        return "null"
    end
end

function host.parse_json(json_str)
    -- Простой парсер JSON (в реальности лучше использовать библиотеку)
    -- Для демонстрации возвращаем заглушку
    return {
        command = "test_command",
        args = {},
        sender_name = "Test Device",
        permissions = "full"
    }
end

-- Обработка пользовательских действий
function host.handle_user_action(action, data)
    if action == "approve_request" then
        return host.approve_request(data.request_id)
    elseif action == "deny_request" then
        return host.deny_request(data.request_id)
    elseif action == "terminate_session" then
        return host.terminate_session(data.session_id)
    elseif action == "get_status" then
        return host.get_status()
    elseif action == "get_sessions" then
        return host.get_active_sessions()
    elseif action == "get_history" then
        return host.get_command_history(data.limit)
    else
        print("Unknown user action: " .. action)
        return false
    end
end

return host