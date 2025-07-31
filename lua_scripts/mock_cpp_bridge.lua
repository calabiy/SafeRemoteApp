-- mock_cpp_bridge.lua - Имитация C++ API для тестирования и отладки

local mock_cpp_bridge = {}

-- Глобальное состояние для имитации
local global_state = {
    devices = {},
    connections = {},
    message_callbacks = {},
    sessions = {},
    notifications = {},
    trusted_devices = {},
    command_results = {}
}

-- Утилиты для работы с JSON
local function simple_json_encode(data)
    if type(data) == "table" then
        local result = "{"
        local first = true
        for k, v in pairs(data) do
            if not first then result = result .. "," end
            result = result .. '"' .. k .. '":' .. simple_json_encode(v)
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

local function simple_json_decode(json_str)
    -- Простая имитация JSON парсинга
    if json_str:match('^%s*{.*}%s*$') then
        return {
            type = "ACCESS_REQUEST",
            sender_id = "test_sender",
            receiver_id = "test_receiver",
            session_id = "test_session_" .. os.time(),
            data = simple_json_encode({
                sender_name = "Test Device",
                permissions = "full",
                device_info = {
                    id = "test_device",
                    name = "Test Device",
                    capabilities = {}
                }
            }),
            timestamp = os.time(),
            -- Дополнительные поля для разных типов сообщений
            approved = true,
            permissions = "full",
            host_info = {
                name = "Mock Host",
                capabilities = {"execute", "file_access"}
            },
            command_id = "cmd_" .. os.time(),
            command = "test_command",
            args = {},
            success = true,
            output = "Mock command executed successfully",
            exit_code = 0,
            reason = "Mock session ended"
        }
    end
    return {}
end

-- Логирование для отладки
local function log(level, message, ...)
    local timestamp = os.date("%H:%M:%S")
    local formatted_message = string.format(message, ...)
    print(string.format("[%s] [%s] %s", timestamp, level, formatted_message))
end

-- Имитация регистрации устройства
function mock_cpp_bridge.register_device(device_id, device_name, public_key)
    log("INFO", "Registering device: %s (%s)", device_name, device_id)
    
    global_state.devices[device_id] = {
        name = device_name,
        public_key = public_key,
        online = true,
        registered_at = os.time()
    }
    
    return true
end

-- Имитация подключения к серверу
function mock_cpp_bridge.connect(server_host, server_port)
    log("INFO", "Connecting to server: %s:%d", server_host, server_port)
    
    -- Имитация задержки подключения
    os.execute("sleep 0.1")
    
    local connection_id = server_host .. ":" .. server_port
    global_state.connections[connection_id] = {
        host = server_host,
        port = server_port,
        connected = true,
        connected_at = os.time()
    }
    
    log("INFO", "Connected successfully to %s", connection_id)
    return true
end

-- Имитация отключения
function mock_cpp_bridge.disconnect()
    log("INFO", "Disconnecting from server")
    
    -- Очистка всех подключений
    for connection_id, _ in pairs(global_state.connections) do
        global_state.connections[connection_id] = nil
        log("INFO", "Disconnected from %s", connection_id)
    end
    
    return true
end

-- Имитация отправки сообщения
function mock_cpp_bridge.send_message(message_json)
    log("INFO", "Sending message: %s", message_json)
    
    local message = simple_json_decode(message_json)
    
    -- Имитация задержки сети
    os.execute("sleep 0.05")
    
    -- Симуляция получения ответа
    mock_cpp_bridge.simulate_response(message)
    
    return true
end

-- Симуляция получения ответа на сообщение
function mock_cpp_bridge.simulate_response(original_message)
    if not original_message or not original_message.type then
        return
    end
    
    local response = {}
    
    if original_message.type == "ACCESS_REQUEST" then
        -- Имитация ответа на запрос доступа
        response = {
            type = "ACCESS_RESPONSE",
            sender_id = original_message.receiver_id,
            receiver_id = original_message.sender_id,
            session_id = original_message.session_id,
            data = simple_json_encode({
                approved = true,
                session_id = original_message.session_id,
                permissions = "full",
                host_info = {
                    name = "Mock Host Device",
                    capabilities = {"execute", "file_access", "screen_share"}
                }
            }),
            timestamp = os.time()
        }
        
        -- Задержка для имитации пользовательского ответа
        os.execute("sleep 0.2")
        
    elseif original_message.type == "COMMAND_EXECUTE" then
        -- Имитация выполнения команды
        local command_data = simple_json_decode(original_message.data)
        
        response = {
            type = "COMMAND_RESULT",
            sender_id = original_message.receiver_id,
            receiver_id = original_message.sender_id,
            session_id = original_message.session_id,
            data = simple_json_encode({
                command_id = command_data.command_id,
                success = true,
                output = "Mock execution of: " .. (command_data.command or "unknown"),
                exit_code = 0,
                execution_time = 0.1
            }),
            timestamp = os.time()
        }
        
        -- Имитация времени выполнения команды
        os.execute("sleep 0.1")
        
    elseif original_message.type == "SESSION_HEARTBEAT" then
        -- Heartbeat обычно не требует ответа, но можем логировать
        log("DEBUG", "Received heartbeat for session: %s", original_message.session_id)
        return
        
    elseif original_message.type == "SESSION_END" then
        -- Подтверждение завершения сессии
        log("INFO", "Session ended: %s", original_message.session_id)
        return
    end
    
    -- Отправка ответа через callback
    if response.type then
        mock_cpp_bridge.deliver_message(response)
    end
end

-- Доставка сообщения через callback
function mock_cpp_bridge.deliver_message(message)
    -- Поиск callback для получателя
    for device_id, callback in pairs(global_state.message_callbacks) do
        if device_id == message.receiver_id then
            log("DEBUG", "Delivering message to %s: %s", device_id, message.type)
            
            -- Небольшая задержка для имитации сетевой доставки
            os.execute("sleep 0.01")
            
            if callback then
                callback(message)
            end
            break
        end
    end
end

-- Установка callback для получения сообщений
function mock_cpp_bridge.set_message_callback(callback)
    -- Сохраняем callback для текущего "устройства"
    -- В реальности нужно было бы знать ID устройства
    local device_id = "current_device_" .. os.time()
    global_state.message_callbacks[device_id] = callback
    
    log("DEBUG", "Message callback set for device: %s", device_id)
    return true
end

-- Имитация выполнения команды
function mock_cpp_bridge.execute_command(command, args_json)
    log("INFO", "Executing command: %s with args: %s", command, args_json)
    
    local args = simple_json_decode(args_json)
    
    -- Имитация различных команд
    local result = {
        success = true,
        output = "",
        exit_code = 0,
        execution_time = 0.1
    }
    
    if command == "ls" or command == "dir" then
        result.output = "file1.txt\nfile2.txt\nfolder1/"
    elseif command == "pwd" then
        result.output = "/mock/current/directory"
    elseif command == "echo" then
        result.output = args.text or "Hello from mock!"
    elseif command == "whoami" then
        result.output = "mockuser"
    elseif command == "date" then
        result.output = os.date("%Y-%m-%d %H:%M:%S")
    elseif command == "ps" then
        result.output = "PID  COMMAND\n1234 mock_process\n5678 another_process"
    elseif command == "fail_test" then
        result.success = false
        result.output = ""
        result.error = "Mock command failed intentionally"
        result.exit_code = 1
    else
        result.output = "Mock execution of unknown command: " .. command
    end
    
    -- Имитация времени выполнения
    local exec_time = math.random(10, 200) / 1000
    os.execute("sleep " .. exec_time)
    result.execution_time = exec_time
    
    log("INFO", "Command completed: %s (exit code: %d)", command, result.exit_code)
    return result
end

-- Имитация показа уведомления
function mock_cpp_bridge.show_notification(notification_json)
    local notification = simple_json_decode(notification_json)
    
    log("INFO", "Showing notification: %s", notification.title or "No title")
    log("INFO", "Message: %s", notification.message or "No message")
    
    -- Сохранение уведомления
    table.insert(global_state.notifications, {
        notification = notification,
        timestamp = os.time()
    })
    
    -- Имитация пользовательского взаимодействия
    if notification.actions then
        log("INFO", "Available actions: %s", table.concat(notification.actions, ", "))
        
        -- Автоматическое одобрение для демонстрации
        if notification.request_id then
            log("INFO", "Auto-approving request: %s", notification.request_id)
            
            -- Имитация клика пользователя через некоторое время
            os.execute("sleep 0.5")
            
            -- Можно добавить логику для автоматической обработки
        end
    end
    
    return true
end

-- Проверка доверенности устройства
function mock_cpp_bridge.is_device_trusted(device_id)
    local trusted = global_state.trusted_devices[device_id] or false
    log("DEBUG", "Checking trust for device %s: %s", device_id, trusted and "trusted" or "not trusted")
    return trusted
end

-- Установка доверенности устройства (для тестирования)
function mock_cpp_bridge.set_device_trusted(device_id, trusted)
    global_state.trusted_devices[device_id] = trusted
    log("INFO", "Device %s trust set to: %s", device_id, trusted and "trusted" or "not trusted")
end

-- Авторизация сессии
function mock_cpp_bridge.authorize_session(session_id, approved)
    log("INFO", "Authorizing session %s: %s", session_id, approved and "approved" or "denied")
    
    global_state.sessions[session_id] = {
        approved = approved,
        authorized_at = os.time()
    }
    
    return true
end

-- Завершение сессии
function mock_cpp_bridge.terminate_session(session_id)
    log("INFO", "Terminating session: %s", session_id)
    
    if global_state.sessions[session_id] then
        global_state.sessions[session_id].terminated_at = os.time()
    end
    
    return true
end

-- Получение статуса мока (для отладки)
function mock_cpp_bridge.get_mock_status()
    return {
        devices = global_state.devices,
        connections = global_state.connections,
        sessions = global_state.sessions,
        notifications = global_state.notifications,
        trusted_devices = global_state.trusted_devices
    }
end

-- Очистка состояния (для тестов)
function mock_cpp_bridge.reset_mock_state()
    global_state = {
        devices = {},
        connections = {},
        message_callbacks = {},
        sessions = {},
        notifications = {},
        trusted_devices = {},
        command_results = {}
    }
    log("INFO", "Mock state reset")
end

-- Установка автоматического режима (для демонстрации)
function mock_cpp_bridge.set_auto_approve(enabled)
    global_state.auto_approve = enabled
    log("INFO", "Auto-approve mode: %s", enabled and "enabled" or "disabled")
end

-- Имитация сетевых задержек
function mock_cpp_bridge.set_network_delay(delay_ms)
    global_state.network_delay = delay_ms or 50
    log("INFO", "Network delay set to: %dms", global_state.network_delay)
end

-- Функция для тестирования различных сценариев
function mock_cpp_bridge.simulate_scenario(scenario_name)
    log("INFO", "Simulating scenario: %s", scenario_name)
    
    if scenario_name == "slow_network" then
        mock_cpp_bridge.set_network_delay(500)
    elseif scenario_name == "connection_failure" then
        -- Имитация сбоя подключения
        global_state.connections = {}
        log("WARNING", "Connection failure simulated")
    elseif scenario_name == "trusted_device" then
        -- Добавление доверенного устройства
        mock_cpp_bridge.set_device_trusted("client_device_001", true)
    end
end

-- Установка мока как глобального cpp_bridge
_G.cpp_bridge = mock_cpp_bridge

log("INFO", "Mock C++ Bridge initialized successfully")

return mock_cpp_bridge