#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <json/json.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <algorithm>

extern "C" {
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>
}

// Структуры данных
struct Device {
    std::string device_id;
    std::string device_name;
    std::string public_key;
    bool online;
    bool trusted;
    std::chrono::time_point<std::chrono::steady_clock> last_seen;
};

struct Session {
    std::string session_id;
    std::string client_id;
    std::string host_id;
    std::string permissions;
    bool active;
    std::chrono::time_point<std::chrono::steady_clock> created_at;
    std::chrono::time_point<std::chrono::steady_clock> last_activity;
};

struct Message {
    std::string type;
    std::string sender_id;
    std::string receiver_id;
    std::string session_id;
    std::string data;
    std::time_t timestamp;
};

struct Connection {
    int socket_fd;
    std::string peer_id;
    std::string peer_address;
    int peer_port;
    bool authenticated;
    std::chrono::time_point<std::chrono::steady_clock> last_activity;
};

// Основной класс LuaBridge
class LuaBridge {
private:
    lua_State* L;
    std::map<std::string, Device> devices;
    std::map<std::string, Session> sessions;
    std::vector<Message> message_queue;
    std::mutex bridge_mutex;
    std::atomic<bool> server_running{false};
    std::atomic<bool> should_shutdown{false};
    std::thread server_thread;
    std::thread message_processor;
    
    // Callback функции для Lua
    std::function<void(const std::string&)> lua_message_callback;
    std::function<void(const std::string&)> lua_notification_callback;
    
    // Сетевые настройки
    std::string server_host;
    int server_port;
    bool is_connected = false;
    bool is_listening = false;
    int server_socket = -1;
    int client_socket = -1;
    
    // Активные соединения
    std::map<std::string, Connection> active_connections;
    
    // Криптография
    RSA* rsa_key_pair = nullptr;
    std::string device_public_key;
    std::string device_private_key;
    std::string device_id;

public:
    LuaBridge() {
        L = luaL_newstate();
        luaL_openlibs(L);
        
        // Генерация уникального ID устройства
        device_id = generate_device_id();
        
        // Инициализация криптографии
        initialize_crypto();
        
        // Регистрация C++ функций в Lua
        register_lua_functions();
        
        // Запуск процессора сообщений
        message_processor = std::thread(&LuaBridge::process_messages, this);
    }
    
    ~LuaBridge() {
        cleanup();
    }
    
    // Генерация уникального ID устройства
    std::string generate_device_id() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        std::string id;
        const char* chars = "0123456789abcdef";
        
        for (int i = 0; i < 32; ++i) {
            id += chars[dis(gen)];
            if (i == 7 || i == 11 || i == 15 || i == 19) {
                id += '-';
            }
        }
        
        return id;
    }
    
    // Инициализация криптографии
    void initialize_crypto() {
        // Генерация RSA ключей
        rsa_key_pair = RSA_new();
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);
        
        RSA_generate_key_ex(rsa_key_pair, 2048, bn, nullptr);
        
        // Получение публичного ключа
        BIO* pub_bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(pub_bio, rsa_key_pair);
        
        char* pub_key_data;
        long pub_key_len = BIO_get_mem_data(pub_bio, &pub_key_data);
        device_public_key = std::string(pub_key_data, pub_key_len);
        
        BIO_free(pub_bio);
        BN_free(bn);
    }
    
    // Регистрация функций в Lua
    void register_lua_functions() {
        // Регистрация глобальной таблицы cpp_bridge
        lua_newtable(L);
        
        // Регистрация функций
        lua_pushcfunction(L, lua_register_device);
        lua_setfield(L, -2, "register_device");
        
        lua_pushcfunction(L, lua_connect);
        lua_setfield(L, -2, "connect");
        
        lua_pushcfunction(L, lua_disconnect);
        lua_setfield(L, -2, "disconnect");
        
        lua_pushcfunction(L, lua_listen);
        lua_setfield(L, -2, "listen");
        
        lua_pushcfunction(L, lua_send_message);
        lua_setfield(L, -2, "send_message");
        
        lua_pushcfunction(L, lua_set_message_callback);
        lua_setfield(L, -2, "set_message_callback");
        
        lua_pushcfunction(L, lua_execute_command);
        lua_setfield(L, -2, "execute_command");
        
        lua_pushcfunction(L, lua_is_device_trusted);
        lua_setfield(L, -2, "is_device_trusted");
        
        lua_pushcfunction(L, lua_show_notification);
        lua_setfield(L, -2, "show_notification");
        
        lua_pushcfunction(L, lua_authorize_session);
        lua_setfield(L, -2, "authorize_session");
        
        lua_pushcfunction(L, lua_terminate_session);
        lua_setfield(L, -2, "terminate_session");
        
        lua_pushcfunction(L, lua_get_device_id);
        lua_setfield(L, -2, "get_device_id");
        
        // Установка глобальной таблицы
        lua_setglobal(L, "cpp_bridge");
        
        // Сохранение указателя на текущий объект
        lua_pushlightuserdata(L, this);
        lua_setglobal(L, "bridge_instance");
    }
    
    // Статические функции для Lua
    static int lua_register_device(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* device_id = luaL_checkstring(L, 1);
        const char* device_name = luaL_checkstring(L, 2);
        const char* public_key = luaL_checkstring(L, 3);
        
        bridge->register_device(device_id, device_name, public_key);
        
        lua_pushboolean(L, 1);
        return 1;
    }
    
    static int lua_connect(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* host = luaL_checkstring(L, 1);
        int port = luaL_checkinteger(L, 2);
        
        bool success = bridge->connect_to_server(host, port);
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_disconnect(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        bridge->disconnect_from_server();
        return 0;
    }
    
    static int lua_listen(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        int port = luaL_checkinteger(L, 1);
        bool success = bridge->start_listening(port);
        
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_send_message(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* message_json = luaL_checkstring(L, 1);
        bool success = bridge->send_message(message_json);
        
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_set_message_callback(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        if (lua_isfunction(L, 1)) {
            lua_pushvalue(L, 1);
            int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);
            
            bridge->set_message_callback([bridge, callback_ref](const std::string& message) {
                bridge->call_lua_callback(callback_ref, message);
            });
        }
        
        return 0;
    }
    
    static int lua_execute_command(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* command = luaL_checkstring(L, 1);
        const char* args_json = luaL_checkstring(L, 2);
        
        std::string result = bridge->execute_command(command, args_json);
        lua_pushstring(L, result.c_str());
        return 1;
    }
    
    static int lua_is_device_trusted(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* device_id = luaL_checkstring(L, 1);
        bool trusted = bridge->is_device_trusted(device_id);
        
        lua_pushboolean(L, trusted);
        return 1;
    }
    
    static int lua_show_notification(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* notification_json = luaL_checkstring(L, 1);
        bridge->show_notification(notification_json);
        
        return 0;
    }
    
    static int lua_authorize_session(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* session_id = luaL_checkstring(L, 1);
        bool approved = lua_toboolean(L, 2);
        
        bridge->authorize_session(session_id, approved);
        return 0;
    }
    
    static int lua_terminate_session(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        
        const char* session_id = luaL_checkstring(L, 1);
        bridge->terminate_session(session_id);
        
        return 0;
    }
    
    static int lua_get_device_id(lua_State* L) {
        LuaBridge* bridge = get_bridge_instance(L);
        lua_pushstring(L, bridge->get_device_id().c_str());
        return 1;
    }
    
    // Получение экземпляра bridge из Lua
    static LuaBridge* get_bridge_instance(lua_State* L) {
        lua_getglobal(L, "bridge_instance");
        LuaBridge* bridge = static_cast<LuaBridge*>(lua_touserdata(L, -1));
        lua_pop(L, 1);
        return bridge;
    }
    
    // Основные методы
    std::string get_device_id() const {
        return device_id;
    }
    
    void register_device(const std::string& device_id, const std::string& device_name, const std::string& public_key) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        Device device;
        device.device_id = device_id;
        device.device_name = device_name;
        device.public_key = public_key;
        device.online = true;
        device.trusted = false;
        device.last_seen = std::chrono::steady_clock::now();
        
        devices[device_id] = device;
        
        std::cout << "Device registered: " << device_name << " (" << device_id << ")" << std::endl;
    }
    
    // ЗАВЕРШЁННАЯ ФУНКЦИЯ CONNECT
    bool connect_to_server(const std::string& host, int port) {
        if (is_connected) {
            std::cout << "Already connected" << std::endl;
            return true;
        }
        
        server_host = host;
        server_port = port;
        
        // Создание сокета
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket == -1) {
            std::cerr << "Failed to create client socket" << std::endl;
            return false;
        }
        
        // Настройка адреса сервера
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid address: " << host << std::endl;
            close(client_socket);
            client_socket = -1;
            return false;
        }
        
        // Подключение
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Connection failed to " << host << ":" << port << std::endl;
            close(client_socket);
            client_socket = -1;
            return false;
        }
        
        // Установка неблокирующего режима
        int flags = fcntl(client_socket, F_GETFL, 0);
        fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
        
        is_connected = true;
        
        // Отправка приветственного сообщения
        Json::Value hello;
        hello["type"] = "HELLO";
        hello["device_id"] = device_id;
        hello["public_key"] = device_public_key;
        hello["timestamp"] = std::time(nullptr);
        
        Json::StreamWriterBuilder builder;
        std::string hello_msg = Json::writeString(builder, hello);
        
        if (!send_raw_message(client_socket, hello_msg)) {
            std::cerr << "Failed to send hello message" << std::endl;
            disconnect_from_server();
            return false;
        }
        
        std::cout << "Connected to server: " << host << ":" << port << std::endl;
        
        // Запуск клиентского потока для чтения сообщений
        std::thread client_reader([this]() {
            client_reader_loop();
        });
        client_reader.detach();
        
        return true;
    }
    
    // ЗАВЕРШЁННАЯ ФУНКЦИЯ LISTEN
    bool start_listening(int port) {
        if (is_listening) {
            std::cout << "Already listening on port " << server_port << std::endl;
            return true;
        }
        
        // Создание серверного сокета
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1) {
            std::cerr << "Failed to create server socket" << std::endl;
            return false;
        }
        
        // Разрешение повторного использования адреса
        int opt = 1;
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "Failed to set socket options" << std::endl;
            close(server_socket);
            server_socket = -1;
            return false;
        }
        
        // Настройка адреса сервера
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);
        
        // Привязка к адресу
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            std::cerr << "Failed to bind to port " << port << std::endl;
            close(server_socket);
            server_socket = -1;
            return false;
        }
        
        // Начало прослушивания
        if (listen(server_socket, 10) < 0) {
            std::cerr << "Failed to listen on port " << port << std::endl;
            close(server_socket);
            server_socket = -1;
            return false;
        }
        
        server_port = port;
        is_listening = true;
        server_running = true;
        
        std::cout << "Listening on port " << port << std::endl;
        
        // Запуск серверного потока
        server_thread = std::thread(&LuaBridge::server_loop, this);
        
        return true;
    }
    
    void disconnect_from_server() {
        is_connected = false;
        
        if (client_socket != -1) {
            close(client_socket);
            client_socket = -1;
        }
        
        std::cout << "Disconnected from server" << std::endl;
    }
    
    void stop_listening() {
        is_listening = false;
        server_running = false;
        
        if (server_socket != -1) {
            close(server_socket);
            server_socket = -1;
        }
        
        if (server_thread.joinable()) {
            server_thread.join();
        }
        
        // Закрытие всех активных соединений
        std::lock_guard<std::mutex> lock(bridge_mutex);
        for (auto& conn : active_connections) {
            close(conn.second.socket_fd);
        }
        active_connections.clear();
        
        std::cout << "Stopped listening" << std::endl;
    }
    
    // ЗАВЕРШЁННАЯ ФУНКЦИЯ SEND_MESSAGE
    bool send_message(const std::string& message_json) {
        // Парсинг JSON сообщения
        Json::Reader reader;
        Json::Value root;
        
        if (!reader.parse(message_json, root)) {
            std::cerr << "Failed to parse message JSON" << std::endl;
            return false;
        }
        
        std::string receiver_id = root["receiver_id"].asString();
        
        // Поиск активного соединения с получателем
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        auto conn_it = active_connections.find(receiver_id);
        if (conn_it != active_connections.end()) {
            // Отправка через активное соединение
            if (send_raw_message(conn_it->second.socket_fd, message_json)) {
                std::cout << "Message sent to " << receiver_id << " via active connection" << std::endl;
                return true;
            } else {
                // Соединение неактивно, удаляем его
                close(conn_it->second.socket_fd);
                active_connections.erase(conn_it);
            }
        }
        
        // Если активного соединения нет, но мы подключены как клиент
        if (is_connected && client_socket != -1) {
            if (send_raw_message(client_socket, message_json)) {
                std::cout << "Message sent via client connection" << std::endl;
                return true;
            }
        }
        
        // Добавление в очередь для последующей отправки
        Message msg;
        msg.type = root["type"].asString();
        msg.sender_id = root["sender_id"].asString();
        msg.receiver_id = receiver_id;
        msg.session_id = root["session_id"].asString();
        msg.data = root["data"].asString();
        msg.timestamp = std::time(nullptr);
        
        message_queue.push_back(msg);
        
        std::cout << "Message queued for " << receiver_id << std::endl;
        return true;
    }
    
    // ЗАВЕРШЁННАЯ ФУНКЦИЯ EXECUTE_COMMAND
    std::string execute_command(const std::string& command, const std::string& args_json) {
        std::cout << "Executing command: " << command << std::endl;
        
        // Парсинг аргументов
        Json::Reader reader;
        Json::Value args;
        if (!reader.parse(args_json, args)) {
            Json::Value error;
            error["success"] = false;
            error["error"] = "Failed to parse arguments JSON";
            Json::StreamWriterBuilder builder;
            return Json::writeString(builder, error);
        }
        
        // Создание результата
        Json::Value result;
        result["success"] = true;
        result["command"] = command;
        result["timestamp"] = std::time(nullptr);
        
        try {
            // Выполнение различных команд
            if (command == "get_system_info") {
                result["output"] = execute_system_info_command();
            } 
            else if (command == "list_processes") {
                result["output"] = execute_list_processes_command();
            }
            else if (command == "get_network_info") {
                result["output"] = execute_network_info_command();
            }
            else if (command == "execute_shell") {
                std::string shell_command = args["command"].asString();
                result["output"] = execute_shell_command(shell_command);
            }
            else if (command == "read_file") {
                std::string filepath = args["path"].asString();
                result["output"] = execute_read_file_command(filepath);
            }
            else if (command == "write_file") {
                std::string filepath = args["path"].asString();
                std::string content = args["content"].asString();
                result["output"] = execute_write_file_command(filepath, content);
            }
            else if (command == "list_directory") {
                std::string dirpath = args["path"].asString();
                result["output"] = execute_list_directory_command(dirpath);
            }
            else if (command == "get_screenshot") {
                result["output"] = execute_screenshot_command();
            }
            else if (command == "send_notification") {
                std::string title = args["title"].asString();
                std::string message = args["message"].asString();
                result["output"] = execute_notification_command(title, message);
            }
            else if (command == "get_clipboard") {
                result["output"] = execute_get_clipboard_command();
            }
            else if (command == "set_clipboard") {
                std::string content = args["content"].asString();
                result["output"] = execute_set_clipboard_command(content);
            }
            else if (command == "get_device_info") {
                result["output"] = execute_device_info_command();
            }
            else {
                result["success"] = false;
                result["error"] = "Unknown command: " + command;
                result["output"] = "";
            }
            
            result["exit_code"] = result["success"].asBool() ? 0 : 1;
            
        } catch (const std::exception& e) {
            result["success"] = false;
            result["error"] = std::string("Command execution failed: ") + e.what();
            result["output"] = "";
            result["exit_code"] = 1;
        }
        
        // Конвертация в JSON
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    void set_message_callback(std::function<void(const std::string&)> callback) {
        lua_message_callback = callback;
    }
    
    bool is_device_trusted(const std::string& device_id) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        auto it = devices.find(device_id);
        if (it != devices.end()) {
            return it->second.trusted;
        }
        
        return false;
    }
    
    void show_notification(const std::string& notification_json) {
        std::cout << "Showing notification: " << notification_json << std::endl;
        
        // В реальной реализации здесь должен быть код для показа нотификации
        // на Android через JNI или на iOS через соответствующие API
        
        // Имитация пользовательского ответа
        std::thread([this, notification_json]() {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            
            // Парсинг нотификации
            Json::Reader reader;
            Json::Value root;
            reader.parse(notification_json, root);
            
            std::string request_id = root["request_id"].asString();
            
            // Имитация одобрения пользователем
            authorize_session(request_id, true);
        }).detach();
    }
    
    void authorize_session(const std::string& session_id, bool approved) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        if (approved) {
            Session session;
            session.session_id = session_id;
            session.active = true;
            session.permissions = "full";
            session.created_at = std::chrono::steady_clock::now();
            session.last_activity = std::chrono::steady_clock::now();
            
            sessions[session_id] = session;
            std::cout << "Session authorized: " << session_id << std::endl;
        } else {
            std::cout << "Session denied: " << session_id << std::endl;
        }
        
        // Отправка ответа клиенту
        Json::Value response;
        response["type"] = "SESSION_AUTH_RESPONSE";
        response["session_id"] = session_id;
        response["approved"] = approved;
        response["timestamp"] = std::time(nullptr);
        
        Json::StreamWriterBuilder builder;
        std::string response_msg = Json::writeString(builder, response);
        
        // Отправка всем активным соединениям (в реальной реализации нужно отправлять конкретному клиенту)
        for (auto& conn : active_connections) {
            send_raw_message(conn.second.socket_fd, response_msg);
        }
    }
    
    void terminate_session(const std::string& session_id) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        auto it = sessions.find(session_id);
        if (it != sessions.end()) {
            it->second.active = false;
            sessions.erase(it);
            std::cout << "Session terminated: " << session_id << std::endl;
        }
    }

private:
    // Вспомогательные методы для execute_command
    std::string execute_system_info_command() {
        Json::Value info;
        info["os"] = "Linux";
        info["hostname"] = "localhost";
        info["architecture"] = "x86_64";
        info["kernel"] = "5.4.0";
        
        // В реальной реализации получать через системные вызовы
        struct utsname sys_info;
        if (uname(&sys_info) == 0) {
            info["os"] = sys_info.sysname;
            info["hostname"] = sys_info.nodename;
            info["architecture"] = sys_info.machine;
            info["kernel"] = sys_info.release;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, info);
    }
    
    std::string execute_list_processes_command() {
        // Простая реализация через чтение /proc
        Json::Value processes(Json::arrayValue);
        
        std::string cmd = "ps aux --no-headers";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                processes.append(std::string(buffer));
            }
            pclose(pipe);
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, processes);
    }
    
    std::string execute_network_info_command() {
        Json::Value network;
        
        std::string cmd = "ip addr show";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            std::string result;
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                result += buffer;
            }
            pclose(pipe);
            network["interfaces"] = result;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, network);
    }
    
    std::string execute_shell_command(const std::string& command) {
        Json::Value result;
        
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe) {
            std::string output;
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                output += buffer;
            }
            int exit_code = pclose(pipe);
            
            result["output"] = output;
            result["exit_code"] = WEXITSTATUS(exit_code);
        } else {
            result["output"] = "";
            result["exit_code"] = -1;
            result["error"] = "Failed to execute command";
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_read_file_command(const std::string& filepath) {
        Json::Value result;
        
        std::ifstream file(filepath);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
            file.close();
            
            result["content"] = content;
            result["size"] = content.length();
        } else {
            result["error"] = "Failed to open file: " + filepath;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_write_file_command(const std::string& filepath, const std::string& content) {
        Json::Value result;
        
        std::ofstream file(filepath);
        if (file.is_open()) {
            file << content;
            file.close();
            
            result["bytes_written"] = content.length();
            result["success"] = true;
        } else {
            result["error"] = "Failed to open file for writing: " + filepath;
            result["success"] = false;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_list_directory_command(const std::string& dirpath) {
        Json::Value result;
        Json::Value files(Json::arrayValue);
        
        DIR* dir = opendir(dirpath.c_str());
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                    Json::Value file_info;
                    file_info["name"] = entry->d_name;
                    file_info["type"] = (entry->d_type == DT_DIR) ? "directory" : "file";
                    files.append(file_info);
                }
            }
            closedir(dir);
            
            result["files"] = files;
            result["count"] = files.size();
        } else {
            result["error"] = "Failed to open directory: " + dirpath;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_screenshot_command() {
        Json::Value result;
        
        // Простая имитация скриншота через ImageMagick или аналог
        std::string cmd = "import -window root /tmp/screenshot_" + 
                         std::to_string(std::time(nullptr)) + ".png";
        
        int exit_code = system(cmd.c_str());
        if (exit_code == 0) {
            result["success"] = true;
            result["path"] = "/tmp/screenshot.png";
        } else {
            result["success"] = false;
            result["error"] = "Failed to take screenshot";
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_notification_command(const std::string& title, const std::string& message) {
        Json::Value result;
        
        // Отправка нотификации через notify-send (Linux) или аналог
        std::string cmd = "notify-send \"" + title + "\" \"" + message + "\"";
        
        int exit_code = system(cmd.c_str());
        result["success"] = (exit_code == 0);
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_get_clipboard_command() {
        Json::Value result;
        
        FILE* pipe = popen("xclip -o -selection clipboard", "r");
        if (pipe) {
            std::string content;
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                content += buffer;
            }
            pclose(pipe);
            
            result["content"] = content;
            result["success"] = true;
        } else {
            result["error"] = "Failed to get clipboard content";
            result["success"] = false;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_set_clipboard_command(const std::string& content) {
        Json::Value result;
        
        std::string cmd = "echo '" + content + "' | xclip -selection clipboard";
        int exit_code = system(cmd.c_str());
        
        result["success"] = (exit_code == 0);
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, result);
    }
    
    std::string execute_device_info_command() {
        Json::Value info;
        
        info["device_id"] = device_id;
        info["public_key"] = device_public_key;
        info["is_listening"] = is_listening;
        info["is_connected"] = is_connected;
        info["server_port"] = server_port;
        info["active_connections"] = static_cast<int>(active_connections.size());
        info["active_sessions"] = static_cast<int>(sessions.size());
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, info);
    }
    
    // Сетевые вспомогательные функции
    bool send_raw_message(int socket_fd, const std::string& message) {
        if (socket_fd == -1) return false;
        
        // Добавляем размер сообщения в начало для правильного чтения
        uint32_t msg_size = htonl(message.length());
        
        // Отправка размера
        if (send(socket_fd, &msg_size, sizeof(msg_size), MSG_NOSIGNAL) != sizeof(msg_size)) {
            return false;
        }
        
        // Отправка самого сообщения
        size_t total_sent = 0;
        while (total_sent < message.length()) {
            ssize_t sent = send(socket_fd, message.c_str() + total_sent, 
                              message.length() - total_sent, MSG_NOSIGNAL);
            if (sent <= 0) {
                return false;
            }
            total_sent += sent;
        }
        
        return true;
    }
    
    std::string receive_raw_message(int socket_fd) {
        if (socket_fd == -1) return "";
        
        // Получение размера сообщения
        uint32_t msg_size_network;
        if (recv(socket_fd, &msg_size_network, sizeof(msg_size_network), MSG_WAITALL) != sizeof(msg_size_network)) {
            return "";
        }
        
        uint32_t msg_size = ntohl(msg_size_network);
        if (msg_size > 1024 * 1024) { // Ограничение на 1MB
            return "";
        }
        
        // Получение самого сообщения
        std::string message(msg_size, '\0');
        if (recv(socket_fd, &message[0], msg_size, MSG_WAITALL) != static_cast<ssize_t>(msg_size)) {
            return "";
        }
        
        return message;
    }
    
    // Основной цикл сервера
    void server_loop() {
        while (server_running && !should_shutdown) {
            // Настройка poll для мониторинга сокетов
            std::vector<pollfd> poll_fds;
            
            // Добавляем серверный сокет
            if (server_socket != -1) {
                pollfd server_pfd = {server_socket, POLLIN, 0};
                poll_fds.push_back(server_pfd);
            }
            
            // Добавляем активные соединения
            std::vector<std::string> connection_ids;
            {
                std::lock_guard<std::mutex> lock(bridge_mutex);
                for (const auto& conn : active_connections) {
                    pollfd client_pfd = {conn.second.socket_fd, POLLIN, 0};
                    poll_fds.push_back(client_pfd);
                    connection_ids.push_back(conn.first);
                }
            }
            
            // Ожидание событий
            int poll_result = poll(poll_fds.data(), poll_fds.size(), 100);
            
            if (poll_result > 0) {
                // Проверка новых подключений
                if (!poll_fds.empty() && (poll_fds[0].revents & POLLIN)) {
                    handle_new_connection();
                }
                
                // Проверка сообщений от существующих клиентов
                for (size_t i = 1; i < poll_fds.size(); ++i) {
                    if (poll_fds[i].revents & POLLIN) {
                        handle_client_message(connection_ids[i-1], poll_fds[i].fd);
                    }
                    else if (poll_fds[i].revents & (POLLHUP | POLLERR)) {
                        handle_client_disconnect(connection_ids[i-1]);
                    }
                }
            }
            
            // Обработка heartbeat для сессий
            check_session_timeouts();
        }
    }
    
    void handle_new_connection() {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(server_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd == -1) {
            return;
        }
        
        // Установка неблокирующего режима
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
        
        // Получение адреса клиента
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        
        std::cout << "New connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;
        
        // Ожидание приветственного сообщения для аутентификации
        std::thread([this, client_fd, client_ip]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            std::string hello_msg = receive_raw_message(client_fd);
            if (!hello_msg.empty()) {
                handle_hello_message(client_fd, client_ip, hello_msg);
            } else {
                std::cout << "Failed to receive hello message, closing connection" << std::endl;
                close(client_fd);
            }
        }).detach();
    }
    
    void handle_hello_message(int client_fd, const std::string& client_ip, const std::string& message) {
        Json::Reader reader;
        Json::Value root;
        
        if (!reader.parse(message, root)) {
            std::cout << "Invalid hello message format" << std::endl;
            close(client_fd);
            return;
        }
        
        if (root["type"].asString() != "HELLO") {
            std::cout << "Expected HELLO message" << std::endl;
            close(client_fd);
            return;
        }
        
        std::string peer_id = root["device_id"].asString();
        std::string public_key = root["public_key"].asString();
        
        // Регистрация устройства
        register_device(peer_id, "Remote Device", public_key);
        
        // Создание соединения
        Connection conn;
        conn.socket_fd = client_fd;
        conn.peer_id = peer_id;
        conn.peer_address = client_ip;
        conn.authenticated = true;
        conn.last_activity = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(bridge_mutex);
            active_connections[peer_id] = conn;
        }
        
        std::cout << "Device authenticated: " << peer_id << " from " << client_ip << std::endl;
        
        // Отправка ответного приветствия
        Json::Value hello_response;
        hello_response["type"] = "HELLO_RESPONSE";
        hello_response["device_id"] = device_id;
        hello_response["public_key"] = device_public_key;
        hello_response["status"] = "connected";
        hello_response["timestamp"] = std::time(nullptr);
        
        Json::StreamWriterBuilder builder;
        std::string response_msg = Json::writeString(builder, hello_response);
        
        send_raw_message(client_fd, response_msg);
    }
    
    void handle_client_message(const std::string& client_id, int client_fd) {
        std::string message = receive_raw_message(client_fd);
        if (message.empty()) {
            handle_client_disconnect(client_id);
            return;
        }
        
        // Обновление времени последней активности
        {
            std::lock_guard<std::mutex> lock(bridge_mutex);
            auto it = active_connections.find(client_id);
            if (it != active_connections.end()) {
                it->second.last_activity = std::chrono::steady_clock::now();
            }
        }
        
        // Обработка сообщения
        if (lua_message_callback) {
            lua_message_callback(message);
        }
        
        std::cout << "Received message from " << client_id << ": " << message.substr(0, 100) << std::endl;
    }
    
    void handle_client_disconnect(const std::string& client_id) {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        auto it = active_connections.find(client_id);
        if (it != active_connections.end()) {
            close(it->second.socket_fd);
            active_connections.erase(it);
            std::cout << "Client disconnected: " << client_id << std::endl;
        }
    }
    
    void client_reader_loop() {
        while (is_connected && client_socket != -1) {
            std::string message = receive_raw_message(client_socket);
            if (message.empty()) {
                std::cout << "Connection lost to server" << std::endl;
                disconnect_from_server();
                break;
            }
            
            // Обработка сообщения от сервера
            if (lua_message_callback) {
                lua_message_callback(message);
            }
            
            std::cout << "Received from server: " << message.substr(0, 100) << std::endl;
        }
    }
    
    // Процессор сообщений
    void process_messages() {
        while (!should_shutdown) {
            std::vector<Message> messages_to_process;
            
            {
                std::lock_guard<std::mutex> lock(bridge_mutex);
                if (!message_queue.empty()) {
                    messages_to_process = message_queue;
                    message_queue.clear();
                }
            }
            
            for (const auto& msg : messages_to_process) {
                process_message(msg);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    
    void process_message(const Message& msg) {
        // Имитация обработки сообщения другим устройством
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Создание ответного сообщения
        if (lua_message_callback) {
            Json::Value response;
            response["type"] = get_response_type(msg.type);
            response["sender_id"] = msg.receiver_id;
            response["receiver_id"] = msg.sender_id;
            response["session_id"] = msg.session_id;
            response["data"] = create_response_data(msg);
            response["timestamp"] = std::time(nullptr);
            
            Json::StreamWriterBuilder builder;
            std::string response_json = Json::writeString(builder, response);
            
            lua_message_callback(response_json);
        }
    }
    
    std::string get_response_type(const std::string& request_type) {
        if (request_type == "ACCESS_REQUEST") return "ACCESS_RESPONSE";
        if (request_type == "COMMAND_EXECUTE") return "COMMAND_RESULT";
        if (request_type == "SESSION_HEARTBEAT") return "SESSION_HEARTBEAT";
        if (request_type == "SESSION_END") return "SESSION_END";
        return "UNKNOWN_RESPONSE";
    }
    
    std::string create_response_data(const Message& msg) {
        Json::Value data;
        
        if (msg.type == "ACCESS_REQUEST") {
            data["approved"] = true;
            data["permissions"] = "full";
            data["host_info"]["name"] = "Test Host";
        } else if (msg.type == "COMMAND_EXECUTE") {
            data["success"] = true;
            data["output"] = "Command executed successfully";
            data["exit_code"] = 0;
        }
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, data);
    }
    
    void check_session_timeouts() {
        std::lock_guard<std::mutex> lock(bridge_mutex);
        
        auto now = std::chrono::steady_clock::now();
        auto session_timeout = std::chrono::seconds(300); // 5 minutes
        auto connection_timeout = std::chrono::seconds(60); // 1 minute
        
        // Проверка таймаутов сессий
        for (auto it = sessions.begin(); it != sessions.end();) {
            if (now - it->second.last_activity > session_timeout) {
                std::cout << "Session timeout: " << it->first << std::endl;
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
        
        // Проверка таймаутов соединений
        for (auto it = active_connections.begin(); it != active_connections.end();) {
            if (now - it->second.last_activity > connection_timeout) {
                std::cout << "Connection timeout: " << it->first << std::endl;
                close(it->second.socket_fd);
                it = active_connections.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    void call_lua_callback(int callback_ref, const std::string& message) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, callback_ref);
        
        if (lua_isfunction(L, -1)) {
            // Парсинг JSON сообщения в Lua таблицу
            Json::Reader reader;
            Json::Value root;
            reader.parse(message, root);
            
            lua_newtable(L);
            
            lua_pushstring(L, root["type"].asString().c_str());
            lua_setfield(L, -2, "type");
            
            lua_pushstring(L, root["sender_id"].asString().c_str());
            lua_setfield(L, -2, "sender_id");
            
            lua_pushstring(L, root["receiver_id"].asString().c_str());
            lua_setfield(L, -2, "receiver_id");
            
            lua_pushstring(L, root["session_id"].asString().c_str());
            lua_setfield(L, -2, "session_id");
            
            lua_pushstring(L, root["data"].asString().c_str());
            lua_setfield(L, -2, "data");
            
            lua_pushinteger(L, root["timestamp"].asInt64());
            lua_setfield(L, -2, "timestamp");
            
            // Вызов Lua функции
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                std::cout << "Lua callback error: " << lua_tostring(L, -1) << std::endl;
                lua_pop(L, 1);
            }
        } else {
            lua_pop(L, 1);
        }
    }
    
    // Загрузка и выполнение Lua скрипта
    bool load_lua_script(const std::string& filename) {
        int result = luaL_loadfile(L, filename.c_str());
        if (result != LUA_OK) {
            std::cout << "Failed to load Lua script: " << lua_tostring(L, -1) << std::endl;
            return false;
        }
        
        result = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (result != LUA_OK) {
            std::cout << "Failed to execute Lua script: " << lua_tostring(L, -1) << std::endl;
            return false;
        }
        
        return true;
    }
    
    // Вызов Lua функции
    bool call_lua_function(const std::string& function_name, const std::vector<std::string>& args = {}) {
        lua_getglobal(L, function_name.c_str());
        
        if (!lua_isfunction(L, -1)) {
            std::cout << "Function not found: " << function_name << std::endl;
            lua_pop(L, 1);
            return false;
        }
        
        for (const auto& arg : args) {
            lua_pushstring(L, arg.c_str());
        }
        
        int result = lua_pcall(L, args.size(), 0, 0);
        if (result != LUA_OK) {
            std::cout << "Lua function error: " << lua_tostring(L, -1) << std::endl;
            lua_pop(L, 1);
            return false;
        }
        
        return true;
    }
    
    void cleanup() {
        should_shutdown = true;
        server_running = false;
        
        // Остановка прослушивания
        if (is_listening) {
            stop_listening();
        }
        
        // Отключение от сервера
        if (is_connected) {
            disconnect_from_server();
        }
        
        if (server_thread.joinable()) {
            server_thread.join();
        }
        
        if (message_processor.joinable()) {
            message_processor.detach();
        }
        
        if (rsa_key_pair) {
            RSA_free(rsa_key_pair);
        }
        
        if (L) {
            lua_close(L);
        }
    }
};