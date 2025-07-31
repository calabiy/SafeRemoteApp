#include "Network.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json/json.h>

Network::Network() : connected(false), ssl_ctx(nullptr), ssl(nullptr) {
    // Инициализация OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Создание SSL контекста
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        std::cerr << "Failed to create SSL context" << std::endl;
    }
}

Network::~Network() {
    disconnect();
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
}

bool Network::connect(const std::string& host, int port) {
    // Создание TCP сокета
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);
    
    if (::connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        close(sock);
        return false;
    }
    
    // Установка SSL соединения
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);
    
    if (SSL_connect(ssl) != 1) {
        std::cerr << "SSL connection failed" << std::endl;
        SSL_free(ssl);
        close(sock);
        return false;
    }
    
    connected = true;
    
    // Запуск потока для получения сообщений
    receive_thread = std::thread(&Network::receiveLoop, this);
    
    return true;
}

void Network::disconnect() {
    if (connected) {
        connected = false;
        if (receive_thread.joinable()) {
            receive_thread.join();
        }
        
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        
        if (sock >= 0) {
            close(sock);
            sock = -1;
        }
    }
}

bool Network::sendMessage(const Message& message) {
    if (!connected) {
        return false;
    }
    
    // Сериализация сообщения в JSON
    Json::Value json_msg;
    json_msg["type"] = static_cast<int>(message.type);
    json_msg["sender_id"] = message.sender_id;
    json_msg["receiver_id"] = message.receiver_id;
    json_msg["session_id"] = message.session_id;
    json_msg["data"] = message.data;
    json_msg["timestamp"] = message.timestamp;
    
    Json::StreamWriterBuilder builder;
    std::string json_str = Json::writeString(builder, json_msg);
    
    // Отправка размера сообщения
    uint32_t msg_size = htonl(json_str.length());
    if (SSL_write(ssl, &msg_size, sizeof(msg_size)) != sizeof(msg_size)) {
        std::cerr << "Failed to send message size" << std::endl;
        return false;
    }
    
    // Отправка самого сообщения
    if (SSL_write(ssl, json_str.c_str(), json_str.length()) != static_cast<int>(json_str.length())) {
        std::cerr << "Failed to send message" << std::endl;
        return false;
    }
    
    return true;
}

void Network::receiveLoop() {
    while (connected) {
        uint32_t msg_size;
        
        // Получение размера сообщения
        int bytes_read = SSL_read(ssl, &msg_size, sizeof(msg_size));
        if (bytes_read != sizeof(msg_size)) {
            if (connected) {
                std::cerr << "Failed to receive message size" << std::endl;
            }
            break;
        }
        
        msg_size = ntohl(msg_size);
        if (msg_size > MAX_MESSAGE_SIZE) {
            std::cerr << "Message size too large: " << msg_size << std::endl;
            break;
        }
        
        // Получение сообщения
        std::vector<char> buffer(msg_size);
        bytes_read = SSL_read(ssl, buffer.data(), msg_size);
        if (bytes_read != static_cast<int>(msg_size)) {
            if (connected) {
                std::cerr << "Failed to receive message" << std::endl;
            }
            break;
        }
        
        // Парсинг JSON
        std::string json_str(buffer.data(), msg_size);
        Json::Value json_msg;
        Json::Reader reader;
        
        if (!reader.parse(json_str, json_msg)) {
            std::cerr << "Failed to parse JSON message" << std::endl;
            continue;
        }
        
        // Создание объекта сообщения
        Message message;
        message.type = static_cast<MessageType>(json_msg["type"].asInt());
        message.sender_id = json_msg["sender_id"].asString();
        message.receiver_id = json_msg["receiver_id"].asString();
        message.session_id = json_msg["session_id"].asString();
        message.data = json_msg["data"].asString();
        message.timestamp = json_msg["timestamp"].asUInt64();
        
        // Вызов callback'а
        if (message_callback) {
            message_callback(message);
        }
    }
}

void Network::setMessageCallback(std::function<void(const Message&)> callback) {
    message_callback = callback;
}

bool Network::isConnected() const {
    return connected;
}

std::string Network::generateSessionId() {
    // нужен криптографически стойкий генератор
    static const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string result;
    result.reserve(32);
    
    for (int i = 0; i < 32; ++i) {
        result += chars[rand() % (sizeof(chars) - 1)];
    }
    
    return result;
}