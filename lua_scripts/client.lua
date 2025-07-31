-- client.lua - Логика клиента (отправитель запросов)

local client = {}
local config = require("config")
local session = require("session")

-- Состояние клиента
client.state = {
    device_id = "",
    device_name = "",
    connected = false,
    current_session = nil,
    pending_requests = {},
    command_queue = {},
    response_callbacks = {}
}

-- Инициализация клиента
function client.init(device_id, device_name)
    client.state.device_id = device_id
    client.state.device_name = device_name
    
    print("Client initialized: " .. device_name .. " (" .. device_id .. ")")
    
    -- Регистрация устройства
    if cpp_bridge then
        cpp_bridge.register_device(device_id, device_name, client.get_public_key())
    end
    
    return true
end

-- Подключение к серверу
function client.connect(server_host, server_port)
    if cpp_bridge then
        local success = cpp_bridge.connect(server_host, server_port)
        if success then
            client.state.connected = true
            cpp_bridge.set_message_callback(client.handle_message)
            print("Connected to server: " .. server_host .. ":" .. server_port)
        else
            print("Failed to connect to server")
        end
        return success
    end
    return false
end

-- Отключение от сервера
function client.disconnect()
    if client.state.current_session then
        client.end_session()
    end
    
    if cpp_bridge then
        cpp_bridge.disconnect()
    end
    
    client.state.connected = false
    print("Disconnected from server")
end

-- Запрос доступа к устройству
function client.request_access(target_device_id, permissions, callback)
    if not client.state.connected then
        print("Not connected to server")
        return false
    end
    
    permissions = permissions or "full"
    
    -- Генерация ID запроса
    local request_id = client.generate_request_id()
    
    -- Создание запроса
    local request = {
        type = "ACCESS_REQUEST",
        sender_id = client.state.device_id,
        receiver_id = target_device_id,
        session_id = request_id,
        data = client.to_json({
            sender_name = client.state.device_name,
            permissions = permissions,
            device_info = {
                id = client.state.device_id,
                name = client.state.device_name,
                capabilities = config.get_capabilities()
            }
        }),
        timestamp = os.time()
    }
    
    -- Сохранение запроса
    client.state.pending_requests[request_id] = {
        request = request,
        callback = callback,
        timestamp = os.time(),
        target_device_id = target_device_id
    }
    
    -- Отправка запроса
    if cpp_bridge then
        cpp_bridge.send_message(client.to_json(request))
    end
    
    print("Access request sent to: " .. target_device_id)
    return request_id
end

-- Обработка входящих сообщений
function client.handle_message(message)
    local msg_type = message.type
    local sender_id = message.sender_id
    local session_id = message.session_id
    
    print("Received message type: " .. msg_type .. " from: " .. sender_id)
    
    if msg_type == "ACCESS_RESPONSE" then
        client.handle_access_response(message)
    elseif msg_type == "COMMAND_RESULT" then
        client.handle_command_result(message)
    elseif msg_type == "SESSION_HEARTBEAT" then
        client.handle_session_heartbeat(message)
    elseif msg_type == "SESSION_END" then
        client.handle_session_end(message)
    else
        print("Unknown message type: " .. msg_type)
    end
end

-- Обработка ответа на запрос доступа
function client.handle_access_response(message)
    local session_id = message.session_id
    local pending_request = client.state.pending_requests[session_id]
    
    if not pending_request then
        print("No pending request found for session: " .. session_id)
        return
    end
    
    local response_data = client.parse_json(message.data)
    if not response_data then
        print("Invalid response data")
        return
    end
    
    if response_data.approved then
        print("Access approved for session: " .. session_id)
        
        -- Создание сессии
        client.state.current_session = session.create(
            session_id,
            client.state.device_id,
            message.sender_id,
            response_data.permissions or "full"
        )
        
        -- Запуск heartbeat
        client.start_heartbeat(session_id)
        
        -- Вызов callback'а
        if pending_request.callback then
            pending_request.callback(true, {
                session_id = session_id,
                host_info = response_data.host_info,
                permissions = response_data.permissions
            })
        end
    else
        print("Access denied for session: " .. session_id)
        print("Reason: " .. (response_data.reason or "Unknown"))
        
        -- Вызов callback'а
        if pending_request.callback then
            pending_request.callback(false, {
                reason = response_data.reason or "Access denied"
            })
        end
    end
    
    -- Удаление запроса из списка ожидающих
    client.state.pending_requests[session_id] = nil
end

-- Выполнение команды
function client.execute_command(command, args, callback)
    if not client.state.current_session then
        print("No active session")
        return false
    end
    
    if not session.is_active(client.state.current_session) then
        print("Session is not active")
        return false
    end
    
    args = args or {}
    
    -- Генерация ID команды
    local command_id = client.generate_command_id()
    
    -- Создание сообщения
    local message = {
        type = "COMMAND_EXECUTE",
        sender_id = client.state.device_id,
        receiver_id = client.state.current_session.host_id,
        session_id = client.state.current_session.session_id,
        data = client.to_json({
            command_id = command_id,
            command = command,
            args = args
        }),
        timestamp = os.time()
    }
    
    -- Сохранение callback'а
    if callback then
        client.state.response_callbacks[command_id] = callback
    end
    
    -- Отправка команды
    if cpp_bridge then
        cpp_bridge.send_message(client.to_json(message))
    end
    
    print("Command sent: " .. command)
    return command_id
end

-- Обработка результата команды
function client.handle_command_result(message)
    local session_id = message.session_id
    
    if not client.state.current_session or 
       client.state.current_session.session_id ~= session_id then
        print("Command result for unknown session: " .. session_id)
        return
    end
    
    local result_data = client.parse_json(message.data)
    if not result_data then
        print("Invalid command result data")
        return
    end
    
    local command_id = result_data.command_id
    local callback = client.state.response_callbacks[command_id]
    
    if callback then
        callback(result_data)
        client.state.response_callbacks[command_id] = nil
    end
    
    print("Command result received: " .. (result_data.success and "SUCCESS" or "FAILED"))
    if result_data.output then
        print("Output: " .. result_data.output)
    end
    if result_data.error then
        print("Error: " .. result_data.error)
    end
end

-- Запуск heartbeat для сессии
function client.start_heartbeat(session_id)
    -- В реальной реализации это должно быть в отдельном потоке
    -- Здесь упрощенная версия
    local heartbeat_data = {
        type = "SESSION_HEARTBEAT",
        sender_id = client.state.device_id,
        receiver_id = client.state.current_session.host_id,
        session_id = session_id,
        data = client.to_json({
            timestamp = os.time()
        }),
        timestamp = os.time()
    }
    
    if cpp_bridge then
        cpp_bridge.send_message(client.to_json(heartbeat_data))
    end
end

-- Завершение сессии
function client.end_session()
    if not client.state.current_session then
        print("No active session to end")
        return false
    end
    
    local session_id = client.state.current_session.session_id
    
    -- Отправка сообщения о завершении
    local message = {
        type = "SESSION_END",
        sender_id = client.state.device_id,
        receiver_id = client.state.current_session.host_id,
        session_id = session_id,
        data = client.to_json({
            reason = "Client initiated"
        }),
        timestamp = os.time()
    }
    
    if cpp_bridge then
        cpp_bridge.send_message(client.to_json(message))
    end
    
    -- Завершение локальной сессии
    session.terminate(client.state.current_session)
    client.state.current_session = nil
    
    print("Session ended: " .. session_id)
    return true
end

-- Обработка heartbeat
function client.handle_session_heartbeat(message)
    if client.state.current_session and 
       client.state.current_session.session_id == message.session_id then
        session.update_activity(client.state.current_session)
    end
end

-- Обработка завершения сессии
function client.handle_session_end(message)
    if client.state.current_session and 
       client.state.current_session.session_id == message.session_id then
        session.terminate(client.state.current_session)
        client.state.current_session = nil
        print("Session ended by host")
    end
end

-- Получение списка доступных устройств
function client.get_available_devices()
    -- В реальной реализации должно запрашивать у сервера
    return {
        {
            device_id = "host_device_1",
            device_name = "Desktop Computer",
            online = true,
            trusted = false
        },
        {
            device_id = "host_device_2",
            device_name = "Laptop",
            online = false,
            trusted = true
        }
    }
end

-- Получение статуса текущей сессии
function client.get_session_status()
    if not client.state.current_session then
        return nil
    end
    
    return {
        session_id = client.state.current_session.session_id,
        host_id = client.state.current_session.host_id,
        permissions = client.state.current_session.permissions,
        active = session.is_active(client.state.current_session),
        created_at = client.state.current_session.created_at,
        last_activity = client.state.current_session.last_activity
    }
end

-- Выполнение предустановленных команд
function client.execute_preset_command(preset_name, callback)
    local presets = config.get_command_presets()
    local preset = presets[preset_name]
    
    if not preset then
        print("Unknown preset: " .. preset_name)
        return false
    end
    
    return client.execute_command(preset.command, preset.args, callback)
end

-- Получение публичного ключа устройства
function client.get_public_key()
    -- В реальной реализации должен возвращать настоящий публичный ключ
    return "CLIENT_PUBLIC_KEY_" .. client.state.device_id
end

-- Генерация ID для запросов
function client.generate_request_id()
    return "req_" .. os.time() .. "_" .. math.random(1000, 9999)
end

-- Генерация ID для команд
function client.generate_command_id()
    return "cmd_" .. os.time() .. "_" .. math.random(1000, 9999)
end

-- Утилиты для работы с JSON
function client.to_json(data)
    if type(data) == "table" then
        local result = "{"
        local first = true
        for k, v in pairs(data) do
            if not first then result = result .. "," end
            result = result .. '"' .. k .. '":' .. client.to_json(v)
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

function client.parse_json(json_str)
    -- Простой парсер JSON (в реальности лучше использовать библиотеку)
    return {
        approved = true,
        permissions = "full",
        host_info = {
            name = "Test Host",
            capabilities = {}
        },
        command_id = "test_cmd_id",
        success = true,
        output = "Command executed successfully",
        exit_code = 0
    }
end

-- Получение статуса клиента
function client.get_status()
    return {
        device_id = client.state.device_id,
        device_name = client.state.device_name,
        connected = client.state.connected,
        has_session = client.state.current_session ~= nil,
        pending_requests = #client.state.pending_requests,
        queued_commands = #client.state.command_queue
    }
end

return client