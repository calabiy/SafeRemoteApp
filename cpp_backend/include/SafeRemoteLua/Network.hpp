#ifndef NETWORK_H
#define NETWORK_H

#include <string>
#include <functional>
#include <thread>
#include <vector>
#include <cstdint>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>

enum class MessageType {
    ACCESS_REQUEST = 1,
    ACCESS_RESPONSE = 2,
    COMMAND_EXECUTE = 3,
    COMMAND_RESULT = 4,
    SESSION_HEARTBEAT = 5,
    SESSION_END = 6,
    DEVICE_REGISTER = 7,
    DEVICE_STATUS = 8
};

struct Message {
    MessageType type;
    std::string sender_id;
    std::string receiver_id;
    std::string session_id;
    std::string data;
    uint64_t timestamp;
    
    Message() : type(MessageType::ACCESS_REQUEST), timestamp(0) {}
};

class Network {
public:
    Network();
    ~Network();
    
    bool connect(const std::string& host, int port);
    void disconnect();
    
    bool sendMessage(const Message& message);
    void setMessageCallback(std::function<void(const Message&)> callback);
    
    bool isConnected() const;
    static std::string generateSessionId();
    
private:
    void receiveLoop();
    
    int sock;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    bool connected;
    std::thread receive_thread;
    std::function<void(const Message&)> message_callback;
    
    static const size_t MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB
};

#endif // NETWORK_H