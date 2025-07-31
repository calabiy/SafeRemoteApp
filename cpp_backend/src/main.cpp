// main.cpp - Точка входа для Android приложения удалённого доступа
// Инициализирует LuaBridge и загружает host.lua или client.lua

#include <jni.h>
#include <android/log.h>
#include <string>
#include <memory>
#include <csignal>
#include <atomic>

// Кроссплатформенная поддержка sleep
#ifdef _WIN32
    #include <windows.h>
    #define SLEEP_MS(ms) Sleep(ms)
#else
    #include <unistd.h>
    #define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

extern "C" {
    #include "lua.h"
    #include "lualib.h"
    #include "lauxlib.h"
}

// Включаем наш модуль аутентификации
#include "Auth.h"

#define LOG_TAG "RemoteAccess"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Глобальный флаг для graceful shutdown
static std::atomic<bool> g_should_exit(false);

// Обработчик сигналов для graceful shutdown
void signalHandler(int signum) {
    LOGI("Received signal %d, shutting down gracefully", signum);
    g_should_exit = true;
}

class LuaBridge {
private:
    lua_State* L;
    bool initialized;
    std::string device_id;
    std::string device_name;
    bool is_host_mode;
    std::unique_ptr<Auth> auth_manager;
    std::string scripts_path;

public:
    LuaBridge() : L(nullptr), initialized(false), is_host_mode(false), scripts_path("lua_scripts/") {}
    
    ~LuaBridge() {
        if (L) {
            lua_close(L);
        }
    }
    
    bool initialize(const std::string& config_path = "auth_config.json") {
        L = luaL_newstate();
        if (!L) {
            LOGE("Failed to create Lua state");
            return false;
        }
        
        // Загрузка стандартных библиотек Lua
        luaL_openlibs(L);
        
        // Инициализация системы аутентификации
        try {
            auth_manager = std::make_unique<Auth>(config_path);
        } catch (const std::exception& e) {
            LOGE("Failed to initialize Auth manager: %s", e.what());
            return false;
        }
        
        // Регистрация C++ функций для Lua
        register_cpp_functions();
        
        initialized = true;
        LOGI("LuaBridge initialized successfully");
        return true;
    }
    
    void setScriptsPath(const std::string& path) {
        scripts_path = path;
    }
    
    void register_cpp_functions() {
        // Создание глобальной таблицы cpp_bridge
        lua_newtable(L);
        
        // Сохраняем указатель на этот объект в Lua state для использования в static функциях
        lua_pushlightuserdata(L, this);
        lua_setfield(L, LUA_REGISTRYINDEX, "bridge_instance");
        
        // Регистрация функций
        lua_pushcfunction(L, lua_register_device);
        lua_setfield(L, -2, "register_device");
        
        lua_pushcfunction(L, lua_connect);
        lua_setfield(L, -2, "connect");
        
        lua_pushcfunction(L, lua_disconnect);
        lua_setfield(L, -2, "disconnect");
        
        lua_pushcfunction(L, lua_send_message);
        lua_setfield(L, -2, "send_message");
        
        lua_pushcfunction(L, lua_set_message_callback);
        lua_setfield(L, -2, "set_message_callback");
        
        lua_pushcfunction(L, lua_execute_command);
        lua_setfield(L, -2, "execute_command");
        
        lua_pushcfunction(L, lua_show_notification);
        lua_setfield(L, -2, "show_notification");
        
        lua_pushcfunction(L, lua_is_device_trusted);
        lua_setfield(L, -2, "is_device_trusted");
        
        lua_pushcfunction(L, lua_authorize_session);
        lua_setfield(L, -2, "authorize_session");
        
        lua_pushcfunction(L, lua_terminate_session);
        lua_setfield(L, -2, "terminate_session");
        
        lua_pushcfunction(L, lua_create_session);
        lua_setfield(L, -2, "create_session");
        
        lua_pushcfunction(L, lua_validate_session);
        lua_setfield(L, -2, "validate_session");
        
        lua_pushcfunction(L, lua_trust_device);
        lua_setfield(L, -2, "trust_device");
        
        lua_pushcfunction(L, lua_revoke_device);
        lua_setfield(L, -2, "revoke_device");
        
        lua_pushcfunction(L, lua_get_device_fingerprint);
        lua_setfield(L, -2, "get_device_fingerprint");
        
        // Установка таблицы как глобальной переменной
        lua_setglobal(L, "cpp_bridge");
    }
    
    bool load_lua_script(const std::string& script_name) {
        if (!initialized) {
            LOGE("LuaBridge not initialized");
            return false;
        }
        
        std::string full_path = scripts_path + script_name;
        int result = luaL_dofile(L, full_path.c_str());
        if (result != LUA_OK) {
            const char* error_msg = lua_tostring(L, -1);
            LOGE("Failed to load Lua script '%s': %s", full_path.c_str(), error_msg ? error_msg : "Unknown error");
            lua_pop(L, 1); // Убираем сообщение об ошибке со стека
            return false;
        }
        
        LOGI("Lua script loaded: %s", full_path.c_str());
        return true;
    }
    
    bool start_host_mode(const std::string& device_id, const std::string& device_name) {
        if (!load_lua_script("host.lua")) {
            return false;
        }
        
        this->device_id = device_id;
        this->device_name = device_name;
        this->is_host_mode = true;
        
        // Генерируем локальные ключи если их нет
        if (auth_manager) {
            auto keys = auth_manager->generateLocalKeys(device_id, device_name);
            if (keys.public_key.empty()) {
                LOGE("Failed to generate local keys");
                return false;
            }
        }
        
        // Вызов host.init()
        lua_getglobal(L, "require");
        lua_pushstring(L, "host");
        if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
            LOGE("Failed to require host: %s", lua_tostring(L, -1));
            return false;
        }
        
        // Получение функции init
        lua_getfield(L, -1, "init");
        if (lua_isnil(L, -1)) {
            LOGE("host.init function not found");
            return false;
        }
        
        lua_pushstring(L, device_id.c_str());
        lua_pushstring(L, device_name.c_str());
        
        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            LOGE("Failed to call host.init(): %s", lua_tostring(L, -1));
            return false;
        }
        
        // Получение функции start_listening
        lua_getfield(L, -2, "start_listening");
        if (lua_isnil(L, -1)) {
            LOGE("host.start_listening function not found");
            return false;
        }
        
        if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
            LOGE("Failed to call host.start_listening(): %s", lua_tostring(L, -1));
            return false;
        }
        
        LOGI("Host mode started successfully");
        return true;
    }
    
    bool start_client_mode(const std::string& device_id, const std::string& device_name) {
        if (!load_lua_script("client.lua")) {
            return false;
        }
        
        this->device_id = device_id;
        this->device_name = device_name;
        this->is_host_mode = false;
        
        // Генерируем локальные ключи если их нет
        if (auth_manager) {
            auto keys = auth_manager->generateLocalKeys(device_id, device_name);
            if (keys.public_key.empty()) {
                LOGE("Failed to generate local keys");
                return false;
            }
        }
        
        // Вызов client.init()
        lua_getglobal(L, "require");
        lua_pushstring(L, "client");
        if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
            LOGE("Failed to require client: %s", lua_tostring(L, -1));
            return false;
        }
        
        // Получение функции init
        lua_getfield(L, -1, "init");
        if (lua_isnil(L, -1)) {
            LOGE("client.init function not found");
            return false;
        }
        
        lua_pushstring(L, device_id.c_str());
        lua_pushstring(L, device_name.c_str());
        
        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            LOGE("Failed to call client.init(): %s", lua_tostring(L, -1));
            return false;
        }
        
        LOGI("Client mode started successfully");
        return true;
    }
    
    bool connect_to_server(const std::string& server_host, int server_port) {
        if (is_host_mode) {
            LOGE("Cannot connect in host mode");
            return false;
        }
        
        // Получение модуля client
        lua_getglobal(L, "require");
        lua_pushstring(L, "client");
        if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
            LOGE("Failed to require client: %s", lua_tostring(L, -1));
            return false;
        }
        
        // Вызов connect
        lua_getfield(L, -1, "connect");
        if (lua_isnil(L, -1)) {
            LOGE("client.connect function not found");
            return false;
        }
        
        lua_pushstring(L, server_host.c_str());
        lua_pushinteger(L, server_port);
        
        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            LOGE("Failed to call client.connect(): %s", lua_tostring(L, -1));
            return false;
        }
        
        bool success = lua_toboolean(L, -1);
        LOGI("Connect result: %s", success ? "SUCCESS" : "FAILED");
        return success;
    }
    
    // Получение указателя на bridge из Lua state
    static LuaBridge* getBridgeFromLua(lua_State* L) {
        lua_getfield(L, LUA_REGISTRYINDEX, "bridge_instance");
        LuaBridge* bridge = static_cast<LuaBridge*>(lua_touserdata(L, -1));
        lua_pop(L, 1);
        return bridge;
    }
    
    // Статические C функции для Lua с реальной логикой
    static int lua_register_device(lua_State* L) {
        const char* device_id = luaL_checkstring(L, 1);
        const char* device_name = luaL_checkstring(L, 2);
        const char* public_key = luaL_checkstring(L, 3);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushboolean(L, false);
            return 1;
        }
        
        LOGI("Registering device: %s (%s)", device_name, device_id);
        
        bool success = bridge->auth_manager->registerDevice(device_id, device_name, public_key);
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_is_device_trusted(lua_State* L) {
        const char* device_id = luaL_checkstring(L, 1);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushboolean(L, false);
            return 1;
        }
        
        LOGI("Checking if device is trusted: %s", device_id);
        
        bool trusted = bridge->auth_manager->isDeviceTrusted(device_id);
        lua_pushboolean(L, trusted);
        return 1;
    }
    
    static int lua_trust_device(lua_State* L) {
        const char* device_id = luaL_checkstring(L, 1);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushboolean(L, false);
            return 1;
        }
        
        LOGI("Trusting device: %s", device_id);
        
        bool success = bridge->auth_manager->trustDevice(device_id);
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_revoke_device(lua_State* L) {
        const char* device_id = luaL_checkstring(L, 1);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushboolean(L, false);
            return 1;
        }
        
        LOGI("Revoking device: %s", device_id);
        
        bool success = bridge->auth_manager->revokeDevice(device_id);
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_create_session(lua_State* L) {
        const char* requester_id = luaL_checkstring(L, 1);
        const char* host_id = luaL_checkstring(L, 2);
        const char* permissions = luaL_checkstring(L, 3);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushnil(L);
            return 1;
        }
        
        LOGI("Creating session: requester=%s, host=%s", requester_id, host_id);
        
        std::string session_id = bridge->auth_manager->createSession(requester_id, host_id, permissions);
        if (!session_id.empty()) {
            lua_pushstring(L, session_id.c_str());
        } else {
            lua_pushnil(L);
        }
        return 1;
    }
    
    static int lua_validate_session(lua_State* L) {
        const char* session_id = luaL_checkstring(L, 1);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushboolean(L, false);
            return 1;
        }
        
        bool valid = bridge->auth_manager->validateSession(session_id);
        lua_pushboolean(L, valid);
        return 1;
    }
    
    static int lua_authorize_session(lua_State* L) {
        const char* session_id = luaL_checkstring(L, 1);
        bool approved = lua_toboolean(L, 2);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushboolean(L, false);
            return 1;
        }
        
        LOGI("Authorizing session: %s, approved: %s", session_id, approved ? "true" : "false");
        
        bool success = bridge->auth_manager->authorizeSession(session_id, approved);
        lua_pushboolean(L, success);
        return 1;
    }
    
    static int lua_terminate_session(lua_State* L) {
        const char* session_id = luaL_checkstring(L, 1);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            return 0;
        }
        
        LOGI("Terminating session: %s", session_id);
        
        bridge->auth_manager->terminateSession(session_id);
        return 0;
    }
    
    static int lua_get_device_fingerprint(lua_State* L) {
        const char* device_id = luaL_checkstring(L, 1);
        
        LuaBridge* bridge = getBridgeFromLua(L);
        if (!bridge || !bridge->auth_manager) {
            LOGE("Bridge or Auth manager not available");
            lua_pushnil(L);
            return 1;
        }
        
        std::string fingerprint = bridge->auth_manager->getDeviceFingerprint(device_id);
        if (!fingerprint.empty()) {
            lua_pushstring(L, fingerprint.c_str());
        } else {
            lua_pushnil(L);
        }
        return 1;
    }
    
    static int lua_connect(lua_State* L) {
        const char* host = luaL_checkstring(L, 1);
        int port = luaL_checkinteger(L, 2);
        
        LOGI("Connecting to: %s:%d", host, port);
        
        // TODO: Здесь должна быть реальная логика подключения
        // Пока просто возвращаем успех
        lua_pushboolean(L, true);
        return 1;
    }
    
    static int lua_disconnect(lua_State* L) {
        LOGI("Disconnecting from server");
        
        // TODO: Здесь должна быть реальная логика отключения
        return 0;
    }
    
    static int lua_send_message(lua_State* L) {
        const char* message = luaL_checkstring(L, 1);
        
        LOGI("Sending message: %s", message);
        
        // TODO: Здесь должна быть реальная логика отправки сообщения
        return 0;
    }
    
    static int lua_set_message_callback(lua_State* L) {
        // TODO: Сохранение callback функции
        LOGI("Setting message callback");
        return 0;
    }
    
    static int lua_execute_command(lua_State* L) {
        const char* command = luaL_checkstring(L, 1);
        const char* args = luaL_checkstring(L, 2);
        
        LOGI("Executing command: %s with args: %s", command, args);
        
        // TODO: Здесь должна быть реальная логика выполнения команды
        // Пока возвращаем заглушку
        lua_newtable(L);
        lua_pushboolean(L, true);
        lua_setfield(L, -2, "success");
        lua_pushstring(L, "Command executed successfully");
        lua_setfield(L, -2, "output");
        lua_pushinteger(L, 0);
        lua_setfield(L, -2, "exit_code");
        
        return 1;
    }
    
    static int lua_show_notification(lua_State* L) {
        const char* notification = luaL_checkstring(L, 1);
        
        LOGI("Showing notification: %s", notification);
        
        // TODO: Здесь должна быть реальная логика показа уведомления
        return 0;
    }
    
    void cleanup() {
        if (auth_manager) {
            auth_manager->cleanupExpiredSessions();
        }
    }
};

// Глобальный экземпляр LuaBridge
static std::unique_ptr<LuaBridge> g_lua_bridge;

// JNI функции для Android
extern "C" {
    
    JNIEXPORT jboolean JNICALL
    Java_com_yourpackage_remoteaccess_MainActivity_initializeLuaBridge(JNIEnv *env, jobject thiz) {
        g_lua_bridge = std::make_unique<LuaBridge>();
        return g_lua_bridge->initialize();
    }
    
    JNIEXPORT jboolean JNICALL
    Java_com_yourpackage_remoteaccess_MainActivity_startHostMode(JNIEnv *env, jobject thiz, 
                                                                 jstring device_id, jstring device_name) {
        if (!g_lua_bridge) {
            LOGE("LuaBridge not initialized");
            return false;
        }
        
        const char* c_device_id = env->GetStringUTFChars(device_id, nullptr);
        const char* c_device_name = env->GetStringUTFChars(device_name, nullptr);
        
        bool result = g_lua_bridge->start_host_mode(c_device_id, c_device_name);
        
        env->ReleaseStringUTFChars(device_id, c_device_id);
        env->ReleaseStringUTFChars(device_name, c_device_name);
        
        return result;
    }
    
    JNIEXPORT jboolean JNICALL
    Java_com_yourpackage_remoteaccess_MainActivity_startClientMode(JNIEnv *env, jobject thiz,
                                                                   jstring device_id, jstring device_name) {
        if (!g_lua_bridge) {
            LOGE("LuaBridge not initialized");
            return false;
        }
        
        const char* c_device_id = env->GetStringUTFChars(device_id, nullptr);
        const char* c_device_name = env->GetStringUTFChars(device_name, nullptr);
        
        bool result = g_lua_bridge->start_client_mode(c_device_id, c_device_name);
        
        env->ReleaseStringUTFChars(device_id, c_device_id);
        env->ReleaseStringUTFChars(device_name, c_device_name);
        
        return result;
    }
    
    JNIEXPORT jboolean JNICALL
    Java_com_yourpackage_remoteaccess_MainActivity_connectToServer(JNIEnv *env, jobject thiz,
                                                                   jstring server_host, jint server_port) {
        if (!g_lua_bridge) {
            LOGE("LuaBridge not initialized");
            return false;
        }
        
        const char* c_server_host = env->GetStringUTFChars(server_host, nullptr);
        
        bool result = g_lua_bridge->connect_to_server(c_server_host, server_port);
        
        env->ReleaseStringUTFChars(server_host, c_server_host);
        
        return result;
    }
    
    JNIEXPORT void JNICALL
    Java_com_yourpackage_remoteaccess_MainActivity_cleanup(JNIEnv *env, jobject thiz) {
        if (g_lua_bridge) {
            g_lua_bridge->cleanup();
        }
    }
}

// Точка входа для нативного приложения (если нужно)
int main(int argc, char* argv[]) {
    LOGI("Remote Access Application Starting");
    
    // Установка обработчика сигналов для graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Инициализация LuaBridge
    g_lua_bridge = std::make_unique<LuaBridge>();
    
    // Настройка путей для скриптов
    if (argc > 4 && std::string(argv[4]) != "") {
        g_lua_bridge->setScriptsPath(argv[4]);
    }
    
    if (!g_lua_bridge->initialize()) {
        LOGE("Failed to initialize LuaBridge");
        return -1;
    }
    
    // Определение режима из аргументов командной строки
    if (argc > 1) {
        std::string mode = argv[1];
        
        if (mode == "host") {
            std::string device_id = argc > 5 ? argv[5] : "host_device_001";
            std::string device_name = argc > 6 ? argv[6] : "Android Host";
            
            if (!g_lua_bridge->start_host_mode(device_id, device_name)) {
                LOGE("Failed to start host mode");
                return -1;
            }
            
            LOGI("Host mode started successfully");
        } else if (mode == "client") {
            std::string device_id = argc > 5 ? argv[5] : "client_device_001";
            std::string device_name = argc > 6 ? argv[6] : "Android Client";
            
            if (!g_lua_bridge->start_client_mode(device_id, device_name)) {
                LOGE("Failed to start client mode");
                return -1;
            }
            
            // Попытка подключения к серверу
            if (argc > 3) {
                std::string server_host = argv[2];
                int server_port = std::stoi(argv[3]);
                
                if (!g_lua_bridge->connect_to_server(server_host, server_port)) {
                    LOGE("Failed to connect to server");
                    return -1;
                }
            }
            
            LOGI("Client mode started successfully");
        } else {
            LOGE("Unknown mode: %s. Use 'host' or 'client'", mode.c_str());
            LOGI("Usage: %s [host|client] [server_host] [server_port] [scripts_path] [device_id] [device_name]", argv[0]);
            return -1;
        }
    } else {
        LOGI("No mode specified.");
        LOGI("Usage: %s [host|client] [server_host] [server_port] [scripts_path] [device_id] [device_name]", argv[0]);
        return -1;
    }
    
    // Основной цикл приложения
    LOGI("Application running. Press Ctrl+C to exit");
    
    while (!g_should_exit) {
        // Обработка событий и очистка просроченных сессий
        if (g_lua_bridge) {
            g_lua_bridge->cleanup();
        }
        
        // Кроссплатформенный sleep на 1 секунду
        SLEEP_MS(1000);
    }
    
    LOGI("Shutting down gracefully");
    g_lua_bridge.reset();
    
    return 0;
}