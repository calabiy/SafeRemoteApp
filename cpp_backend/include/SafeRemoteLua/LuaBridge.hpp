#ifndef LUABRIDGE_HPP
#define LUABRIDGE_HPP

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
#include <ctime>
#include <random>
#include <fstream>
#include <sstream>

// System includes
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <algorithm>

// External libraries
#include <json/json.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

extern "C" {
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>
}

/**
 * @brief Structure representing a remote device in the network
 */
struct Device {
    std::string device_id;      ///< Unique device identifier
    std::string device_name;    ///< Human-readable device name
    std::string public_key;     ///< RSA public key for encryption
    bool online;               ///< Current online status
    bool trusted;              ///< Whether device is trusted for automatic connections
    std::chrono::time_point<std::chrono::steady_clock> last_seen; ///< Last activity timestamp
};

/**
 * @brief Structure representing an active session between devices
 */
struct Session {
    std::string session_id;     ///< Unique session identifier
    std::string client_id;      ///< Client device ID
    std::string host_id;        ///< Host device ID
    std::string permissions;    ///< Session permissions (e.g., "full", "limited")
    bool active;               ///< Whether session is currently active
    std::chrono::time_point<std::chrono::steady_clock> created_at;    ///< Session creation time
    std::chrono::time_point<std::chrono::steady_clock> last_activity; ///< Last activity timestamp
};

/**
 * @brief Structure representing a message in the system
 */
struct Message {
    std::string type;          ///< Message type (e.g., "ACCESS_REQUEST", "COMMAND_EXECUTE")
    std::string sender_id;     ///< Sender device ID
    std::string receiver_id;   ///< Receiver device ID
    std::string session_id;    ///< Associated session ID
    std::string data;          ///< Message payload (JSON string)
    std::time_t timestamp;     ///< Message timestamp
};

/**
 * @brief Structure representing an active network connection
 */
struct Connection {
    int socket_fd;             ///< Socket file descriptor
    std::string peer_id;       ///< Connected peer device ID
    std::string peer_address;  ///< Peer IP address
    int peer_port;            ///< Peer port number
    bool authenticated;        ///< Whether connection is authenticated
    std::chrono::time_point<std::chrono::steady_clock> last_activity; ///< Last activity timestamp
};

/**
 * @brief Main LuaBridge class providing device-to-device communication bridge
 * 
 * This class implements a communication bridge that allows devices to connect
 * and exchange messages securely. It provides both server (listening) and client
 * (connecting) functionality, with Lua scripting integration for custom behavior.
 */
class LuaBridge {
private:
    // Lua state
    lua_State* L;              ///< Lua interpreter state
    
    // Data storage
    std::map<std::string, Device> devices;      ///< Registered devices
    std::map<std::string, Session> sessions;    ///< Active sessions
    std::vector<Message> message_queue;         ///< Queued messages for processing
    
    // Threading and synchronization
    std::mutex bridge_mutex;                    ///< Main synchronization mutex
    std::atomic<bool> server_running{false};   ///< Server thread running flag
    std::atomic<bool> should_shutdown{false};  ///< Shutdown signal flag
    std::thread server_thread;                  ///< Server listening thread
    std::thread message_processor;              ///< Message processing thread
    
    // Lua callback functions
    std::function<void(const std::string&)> lua_message_callback;      ///< Message received callback
    std::function<void(const std::string&)> lua_notification_callback; ///< Notification callback
    
    // Network configuration
    std::string server_host;   ///< Server host for client connections
    int server_port;          ///< Server port
    bool is_connected;        ///< Client connection status
    bool is_listening;        ///< Server listening status
    int server_socket;        ///< Server socket file descriptor
    int client_socket;        ///< Client socket file descriptor
    
    // Active connections
    std::map<std::string, Connection> active_connections; ///< Active peer connections
    
    // Cryptography
    RSA* rsa_key_pair;        ///< RSA key pair for encryption
    std::string device_public_key;  ///< Device public key (PEM format)
    std::string device_private_key; ///< Device private key (PEM format)
    std::string device_id;    ///< Unique device identifier

public:
    /**
     * @brief Constructor - initializes Lua state and starts message processor
     */
    LuaBridge();
    
    /**
     * @brief Destructor - cleans up resources and stops all threads
     */
    ~LuaBridge();

    // Device and crypto management
    /**
     * @brief Generate a unique device identifier
     * @return UUID-style device ID string
     */
    std::string generate_device_id();
    
    /**
     * @brief Initialize RSA cryptography for secure communications
     */
    void initialize_crypto();
    
    /**
     * @brief Get this device's unique identifier
     * @return Device ID string
     */
    std::string get_device_id() const;

    // Lua integration
    /**
     * @brief Register C++ functions in Lua global scope
     */
    void register_lua_functions();
    
    /**
     * @brief Load and execute a Lua script file
     * @param filename Path to Lua script file
     * @return true if successful, false otherwise
     */
    bool load_lua_script(const std::string& filename);
    
    /**
     * @brief Call a Lua function by name with string arguments
     * @param function_name Name of Lua function to call
     * @param args Vector of string arguments
     * @return true if successful, false otherwise
     */
    bool call_lua_function(const std::string& function_name, const std::vector<std::string>& args = {});

    // Device management
    /**
     * @brief Register a remote device
     * @param device_id Unique device identifier
     * @param device_name Human-readable device name
     * @param public_key Device's RSA public key (PEM format)
     */
    void register_device(const std::string& device_id, const std::string& device_name, const std::string& public_key);
    
    /**
     * @brief Check if a device is trusted for automatic connections
     * @param device_id Device identifier to check
     * @return true if trusted, false otherwise
     */
    bool is_device_trusted(const std::string& device_id);

    // Network operations
    /**
     * @brief Connect to a remote server as client
     * @param host Server hostname or IP address
     * @param port Server port number
     * @return true if connection successful, false otherwise
     */
    bool connect_to_server(const std::string& host, int port);
    
    /**
     * @brief Disconnect from remote server
     */
    void disconnect_from_server();
    
    /**
     * @brief Start listening for incoming connections as server
     * @param port Port number to listen on
     * @return true if listening started successfully, false otherwise
     */
    bool start_listening(int port);
    
    /**
     * @brief Stop listening for incoming connections
     */
    void stop_listening();

    // Message handling
    /**
     * @brief Send a message to a remote device
     * @param message_json JSON-formatted message string
     * @return true if message sent successfully, false otherwise
     */
    bool send_message(const std::string& message_json);
    
    /**
     * @brief Set callback function for received messages
     * @param callback Function to call when message is received
     */
    void set_message_callback(std::function<void(const std::string&)> callback);

    // Command execution
    /**
     * @brief Execute a system command with arguments
     * @param command Command name to execute
     * @param args_json JSON string containing command arguments
     * @return JSON string containing command result
     */
    std::string execute_command(const std::string& command, const std::string& args_json);

    // Session management
    /**
     * @brief Authorize or deny a session request
     * @param session_id Session identifier
     * @param approved Whether to approve the session
     */
    void authorize_session(const std::string& session_id, bool approved);
    
    /**
     * @brief Terminate an active session
     * @param session_id Session identifier to terminate
     */
    void terminate_session(const std::string& session_id);

    // UI integration
    /**
     * @brief Show a notification to the user
     * @param notification_json JSON-formatted notification data
     */
    void show_notification(const std::string& notification_json);

private:
    // Static Lua binding functions
    static int lua_register_device(lua_State* L);
    static int lua_connect(lua_State* L);
    static int lua_disconnect(lua_State* L);
    static int lua_listen(lua_State* L);
    static int lua_send_message(lua_State* L);
    static int lua_set_message_callback(lua_State* L);
    static int lua_execute_command(lua_State* L);
    static int lua_is_device_trusted(lua_State* L);
    static int lua_show_notification(lua_State* L);
    static int lua_authorize_session(lua_State* L);
    static int lua_terminate_session(lua_State* L);
    static int lua_get_device_id(lua_State* L);
    
    /**
     * @brief Get LuaBridge instance from Lua state
     * @param L Lua state pointer
     * @return Pointer to LuaBridge instance
     */
    static LuaBridge* get_bridge_instance(lua_State* L);

    // Command execution helpers
    std::string execute_system_info_command();
    std::string execute_list_processes_command();
    std::string execute_network_info_command();
    std::string execute_shell_command(const std::string& command);
    std::string execute_read_file_command(const std::string& filepath);
    std::string execute_write_file_command(const std::string& filepath, const std::string& content);
    std::string execute_list_directory_command(const std::string& dirpath);
    std::string execute_screenshot_command();
    std::string execute_notification_command(const std::string& title, const std::string& message);
    std::string execute_get_clipboard_command();
    std::string execute_set_clipboard_command(const std::string& content);
    std::string execute_device_info_command();

    // Network helpers
    /**
     * @brief Send raw message over socket with length prefix
     * @param socket_fd Socket file descriptor
     * @param message Message to send
     * @return true if successful, false otherwise
     */
    bool send_raw_message(int socket_fd, const std::string& message);
    
    /**
     * @brief Receive raw message from socket with length prefix
     * @param socket_fd Socket file descriptor
     * @return Received message string, empty if failed
     */
    std::string receive_raw_message(int socket_fd);

    // Server operation handlers
    /**
     * @brief Main server loop for handling connections and messages
     */
    void server_loop();
    
    /**
     * @brief Handle new incoming connection
     */
    void handle_new_connection();
    
    /**
     * @brief Handle HELLO message from new client
     * @param client_fd Client socket file descriptor
     * @param client_ip Client IP address
     * @param message HELLO message content
     */
    void handle_hello_message(int client_fd, const std::string& client_ip, const std::string& message);
    
    /**
     * @brief Handle message from connected client
     * @param client_id Client device ID
     * @param client_fd Client socket file descriptor
     */
    void handle_client_message(const std::string& client_id, int client_fd);
    
    /**
     * @brief Handle client disconnection
     * @param client_id Client device ID
     */
    void handle_client_disconnect(const std::string& client_id);
    
    /**
     * @brief Client reader loop for receiving server messages
     */
    void client_reader_loop();

    // Message processing
    /**
     * @brief Main message processing loop
     */
    void process_messages();
    
    /**
     * @brief Process a single message
     * @param msg Message to process
     */
    void process_message(const Message& msg);
    
    /**
     * @brief Get appropriate response type for request type
     * @param request_type Original request message type
     * @return Corresponding response message type
     */
    std::string get_response_type(const std::string& request_type);
    
    /**
     * @brief Create response data for a message
     * @param msg Original message
     * @return JSON response data string
     */
    std::string create_response_data(const Message& msg);

    // Session and connection management
    /**
     * @brief Check for and handle session/connection timeouts
     */
    void check_session_timeouts();
    
    /**
     * @brief Call Lua callback function with message data
     * @param callback_ref Lua registry reference to callback function
     * @param message Message to pass to callback
     */
    void call_lua_callback(int callback_ref, const std::string& message);

    // Cleanup
    /**
     * @brief Clean up all resources and stop threads
     */
    void cleanup();
};

#endif // LUABRIDGE_HPP