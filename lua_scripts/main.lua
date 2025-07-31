#!/usr/bin/env lua
-- main.lua - Запуск системы удалённого доступа полностью на Lua
-- Использует mock_cpp_bridge.lua для имитации C++ API

-- Загрузка мока C++ API
require("mock_cpp_bridge")

-- Глобальные переменные
local args = {...}
local mode = args[1] or "demo"

-- Функция для красивого логирования
local function log(level, message, ...)
    local timestamp = os.date("%H:%M:%S")
    local colors = {
        INFO = "\27[32m",    -- Зеленый
        WARNING = "\27[33m", -- Желтый
        ERROR = "\27[31m",   -- Красный
        DEBUG = "\27[36m",   -- Голубой
        RESET = "\27[0m"
    }
    
    local color = colors[level] or colors.RESET
    local formatted_message = string.format(message, ...)
    print(string.format("%s[%s] [%s] %s%s", color, timestamp, level, formatted_message, colors.RESET))
end

-- Функция для создания разделителя
local function print_separator(title)
    local separator = string.rep("=", 60)
    log("INFO", "%s", separator)
    if title then
        log("INFO", "%s %s %s", string.rep("=", 20), title, string.rep("=", 20))
    end
    log("INFO", "%s", separator)
end

-- Демонстрация работы host + client
local function run_demo()
    print_separator("DEMO MODE: HOST + CLIENT")
    
    -- Инициализация мока
    cpp_bridge.reset_mock_state()
    cpp_bridge.set_auto_approve(true)
    cpp_bridge.set_network_delay(100)
    
    log("INFO", "Starting demo with host and client in same environment")
    
    -- Загрузка модулей
    local host = require("host")
    local client = require("client")
    
    -- Инициализация хоста
    log("INFO", "Initializing host...")
    host.init("host_device_001", "Demo Host Device")
    host.start_listening()
    
    -- Небольшая задержка
    os.execute("sleep 0.2")
    
    -- Инициализация клиента
    log("INFO", "Initializing client...")
    client.init("client_device_001", "Demo Client Device")
    client.connect("localhost", 8080)
    
    -- Небольшая задержка
    os.execute("sleep 0.2")
    
    -- Демонстрация запроса доступа
    log("INFO", "Client requesting access to host...")
    client.request_access("host_device_001", "full", function(success, result)
        if success then
            log("INFO", "Access granted! Session ID: %s", result.session_id)
            
            -- Демонстрация выполнения команд
            log("INFO", "Executing demo commands...")
            
            -- Команда 1: ls
            client.execute_command("ls", {}, function(result)
                log("INFO", "Command 'ls' result: %s", result.output or "No output")
            end)
            
            os.execute("sleep 0.3")
            
            -- Команда 2: pwd
            client.execute_command("pwd", {}, function(result)
                log("INFO", "Command 'pwd' result: %s", result.output or "No output")
            end)
            
            os.execute("sleep 0.3")
            
            -- Команда 3: echo
            client.execute_command("echo", {text = "Hello from remote client!"}, function(result)
                log("INFO", "Command 'echo' result: %s", result.output or "No output")
            end)
            
            os.execute("sleep 0.3")
            
            -- Команда 4: whoami
            client.execute_command("whoami", {}, function(result)
                log("INFO", "Command 'whoami' result: %s", result.output or "No output")
            end)
            
            os.execute("sleep 0.5")
            
            -- Завершение сессии
            log("INFO", "Ending session...")
            client.end_session()
            
        else
            log("ERROR", "Access denied: %s", result.reason or "Unknown reason")
        end
    end)
    
    -- Ожидание завершения демонстрации
    os.execute("sleep 2")
    
    -- Показ статистики
    print_separator("DEMO STATISTICS")
    local mock_status = cpp_bridge.get_mock_status()
    
    log("INFO", "Registered devices: %d", #mock_status.devices)
    log("INFO", "Active connections: %d", #mock_status.connections)
    log("INFO", "Total sessions: %d", #mock_status.sessions)
    log("INFO", "Notifications shown: %d", #mock_status.notifications)
    
    log("INFO", "Demo completed successfully!")
end

-- Запуск только хоста
local function run_host()
    print_separator("HOST MODE")
    
    local host = require("host")
    
    local device_id = args[2] or "host_device_001"
    local device_name = args[3] or "Lua Host Device"
    
    log("INFO", "Starting host mode...")
    log("INFO", "Device ID: %s", device_id)
    log("INFO", "Device Name: %s", device_name)
    
    -- Инициализация
    if not host.init(device_id, device_name) then
        log("ERROR", "Failed to initialize host")
        return false
    end
    
    -- Запуск прослушивания
    if not host.start_listening() then
        log("ERROR", "Failed to start listening")
        return false
    end
    
    log("INFO", "Host is running and listening for connections...")
    log("INFO", "Press Ctrl+C to stop")
    
    -- Основной цикл
    while true do
        os.execute("sleep 1")
        
        -- Очистка неактивных сессий каждые 30 секунд
        if os.time() % 30 == 0 then
            local cleaned = host.cleanup_sessions()
            if cleaned > 0 then
                log("INFO", "Cleaned up %d inactive sessions", cleaned)
            end
        end
        
        -- Показ статуса каждые 10 секунд
        if os.time() % 10 == 0 then
            local status = host.get_status()
            log("DEBUG", "Status: %d active sessions, %d pending requests", 
                status.active_sessions, status.pending_requests)
        end
    end
end

-- Запуск только клиента
local function run_client()
    print_separator("CLIENT MODE")
    
    local client = require("client")
    
    local device_id = args[2] or "client_device_001"
    local device_name = args[3] or "Lua Client Device"
    local server_host = args[4] or "localhost"
    local server_port = tonumber(args[5]) or 8080
    local target_device = args[6] or "host_device_001"
    
    log("INFO", "Starting client mode...")
    log("INFO", "Device ID: %s", device_id)
    log("INFO", "Device Name: %s", device_name)
    log("INFO", "Server: %s:%d", server_host, server_port)
    log("INFO", "Target device: %s", target_device)
    
    -- Инициализация
    if not client.init(device_id, device_name) then
        log("ERROR", "Failed to initialize client")
        return false
    end
    
    -- Подключение к серверу
    if not client.connect(server_host, server_port) then
        log("ERROR", "Failed to connect to server")
        return false
    end
    
    log("INFO", "Connected to server successfully")
    
    -- Запрос доступа
    log("INFO", "Requesting access to target device...")
    client.request_access(target_device, "full", function(success, result)
        if success then
            log("INFO", "Access granted! Session ID: %s", result.session_id)
            
            -- Интерактивный режим
            log("INFO", "Entering interactive mode. Type 'help' for commands.")
            
            while true do
                io.write("remote> ")
                local input = io.read()
                
                if not input or input == "exit" or input == "quit" then
                    break
                elseif input == "help" then
                    print("Available commands:")
                    print("  ls, pwd, whoami, date, ps - System commands")
                    print("  echo <text> - Echo text")
                    print("  status - Show session status")
                    print("  help - Show this help")
                    print("  exit, quit - Exit client")
                elseif input == "status" then
                    local status = client.get_session_status()
                    if status then
                        log("INFO", "Session: %s, Host: %s, Permissions: %s", 
                            status.session_id, status.host_id, status.permissions)
                    else
                        log("WARNING", "No active session")
                    end
                elseif input ~= "" then
                    -- Разбор команды
                    local parts = {}
                    for part in input:gmatch("%S+") do
                        table.insert(parts, part)
                    end
                    
                    local command = parts[1]
                    local args = {}
                    
                    if command == "echo" then
                        args.text = table.concat(parts, " ", 2)
                    end
                    
                    -- Выполнение команды
                    client.execute_command(command, args, function(result)
                        if result.success then
                            if result.output and result.output ~= "" then
                                print(result.output)
                            end
                        else
                            log("ERROR", "Command failed: %s", result.error or "Unknown error")
                        end
                    end)
                end
            end
            
            -- Завершение сессии
            log("INFO", "Ending session...")
            client.end_session()
            
        else
            log("ERROR", "Access denied: %s", result.reason or "Unknown reason")
        end
    end)
    
    -- Отключение
    client.disconnect()
    log("INFO", "Client disconnected")
end

-- Тестовый режим
local function run_test()
    print_separator("TEST MODE")
    
    -- Сброс состояния
    cpp_bridge.reset_mock_state()
    
    -- Тест 1: Базовая функциональность
    log("INFO", "Test 1: Basic functionality")
    
    local host = require("host")
    local client = require("client")
    
    -- Инициализация
    host.init("test_host", "Test Host")
    host.start_listening()
    
    client.init("test_client", "Test Client")
    client.connect("localhost", 8080)
    
    -- Тест запроса доступа
    local access_granted = false
    client.request_access("test_host", "full", function(success, result)
        access_granted = success
        if success then
            log("INFO", "✓ Access request successful")
        else
            log("ERROR", "✗ Access request failed")
        end
    end)
    
    os.execute("sleep 0.2")
    
    -- Тест 2: Выполнение команд
    if access_granted then
        log("INFO", "Test 2: Command execution")
        
        local commands = {"ls", "pwd", "whoami", "date"}
        for _, cmd in ipairs(commands) do
            client.execute_command(cmd, {}, function(result)
                if result.success then
                    log("INFO", "✓ Command '%s' executed successfully", cmd)
                else
                    log("ERROR", "✗ Command '%s' failed", cmd)
                end
            end)
            os.execute("sleep 0.1")
        end
        
        -- Тест команды с ошибкой
        client.execute_command("fail_test", {}, function(result)
            if not result.success then
                log("INFO", "✓ Error handling works correctly")
            else
                log("ERROR", "✗ Error handling failed")
            end
        end)
    end
    
    os.execute("sleep 0.5")
    
    -- Тест 3: Завершение сессии
    log("INFO", "Test 3: Session termination")
    if client.end_session() then
        log("INFO", "✓ Session ended successfully")
    else
        log("ERROR", "✗ Session termination failed")
    end
    
    -- Тест 4: Статистика
    log("INFO", "Test 4: Statistics")
    local mock_status = cpp_bridge.get_mock_status()
    log("INFO", "Mock state: %d devices, %d sessions", #mock_status.devices, #mock_status.sessions)
    
    log("INFO", "All tests completed!")
end

-- Показ справки
local function show_help()
    print_separator("HELP")
    print("Usage: lua main.lua [mode] [options...]")
    print("")
    print("Modes:")
    print("  demo                          - Run host + client demo")
    print("  host [device_id] [device_name] - Run as host")
    print("  client [device_id] [device_name] [server_host] [server_port] [target_device] - Run as client")
    print("  test                          - Run automated tests")
    print("  help                          - Show this help")
    print("")
    print("Examples:")
    print("  lua main.lua demo")
    print("  lua main.lua host my_host \"My Host Device\"")
    print("  lua main.lua client my_client \"My Client\" localhost 8080 my_host")
    print("  lua main.lua test")
    print("")
    print("Interactive client commands:")
    print("  ls, pwd, whoami, date, ps     - System commands")
    print("  echo <text>                   - Echo text")
    print("  status                        - Show session status")
    print("  help                          - Show available commands")
    print("  exit, quit                    - Exit client")
end

-- Основная функция
local function main()
    print_separator("LUA REMOTE ACCESS SYSTEM")
    
    log("INFO", "Starting Lua Remote Access System")
    log("INFO", "Mode: %s", mode)
    
    -- Выбор режима
    if mode == "demo" then
        run_demo()
    elseif mode == "host" then
        run_host()
    elseif mode == "client" then
        run_client()
    elseif mode == "test" then
        run_test()
    elseif mode == "help" then
        show_help()
    else
        log("ERROR", "Unknown mode: %s", mode)
        show_help()
        return 1
    end
    
    return 0
end

-- Обработка Ctrl+C
local function signal_handler()
    print_separator("SHUTDOWN")
        log("INFO", "Shutting down gracefully...")
    os.exit(0)
end

-- Установка обработчика сигнала прерывания (работает не везде)
if pcall(require, "posix.signal") then
    local signal = require("posix.signal")
    signal.signal(signal.SIGINT, signal_handler)
end

-- Запуск main
main()
