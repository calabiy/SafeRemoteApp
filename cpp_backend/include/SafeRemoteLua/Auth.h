#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <unordered_map>
#include <vector>
#include <json/json.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

enum class SessionStatus {
    PENDING,
    ACTIVE,
    EXPIRED,
    DENIED,
    TERMINATED,
    REVOKED
};

struct DeviceInfo {
    std::string device_id;
    std::string device_name;
    std::string public_key;      // PEM формат
    std::string private_key;     // PEM формат (только для локального устройства)
    bool trusted;
    uint64_t last_seen;
    uint64_t created_at;
    std::string fingerprint;     // SHA-256 отпечаток публичного ключа
};

struct Session {
    std::string session_id;
    std::string requester_id;
    std::string host_id;
    std::string permissions;
    SessionStatus status;
    uint64_t created_at;
    uint64_t last_activity;
    uint64_t expires_at;
    std::string challenge;       // Для верификации подписи
    std::string signature;       // Подпись challenge
};

struct KeyPair {
    std::string public_key;      // PEM формат
    std::string private_key;     // PEM формат
    std::string fingerprint;     // SHA-256 отпечаток
};

class Auth {
private:
    static const uint64_t SESSION_TIMEOUT = 3600;  // 1 час
    static const int RSA_KEY_SIZE = 2048;
    
    std::unordered_map<std::string, DeviceInfo> devices;
    std::unordered_map<std::string, Session> active_sessions;
    std::string config_file;
    std::string local_device_id;
    KeyPair local_keys;

    // Внутренние методы
    std::string generateSessionId();
    uint64_t getCurrentTimestamp();
    void loadConfig();
    void saveConfig();
    
    // Криптографические методы
    EVP_PKEY* loadPublicKeyFromPEM(const std::string& pem_key);
    EVP_PKEY* loadPrivateKeyFromPEM(const std::string& pem_key);
    std::string calculateFingerprint(const std::string& public_key);
    std::string generateChallenge();

public:
    Auth(const std::string& config_path);
    ~Auth();

    // Управление устройствами
    bool registerDevice(const std::string& device_id, const std::string& device_name, 
                       const std::string& public_key);
    bool trustDevice(const std::string& device_id);
    bool revokeDevice(const std::string& device_id);
    bool isDeviceTrusted(const std::string& device_id);
    std::vector<DeviceInfo> getDevices() const;
    
    // Управление сессиями
    std::string createSession(const std::string& requester_id, const std::string& host_id,
                            const std::string& permissions);
    bool authorizeSession(const std::string& session_id, bool approved);
    bool validateSession(const std::string& session_id);
    void terminateSession(const std::string& session_id);
    std::vector<Session> getActiveSessions() const;
    void cleanupExpiredSessions();
    bool hasPermission(const std::string& session_id, const std::string& permission);
    
    // Криптографические операции
    KeyPair generateKeyPair();
    KeyPair generateLocalKeys(const std::string& device_id, const std::string& device_name);
    std::string getLocalDeviceId() const { return local_device_id; }
    std::string getLocalPublicKey() const { return local_keys.public_key; }
    
    // Подписи и верификация
    std::string signData(const std::string& data, const std::string& private_key);
    bool verifySignature(const std::string& data, const std::string& signature, 
                        const std::string& public_key);
    std::string createAuthChallenge(const std::string& session_id);
    bool verifyAuthChallenge(const std::string& session_id, const std::string& signature);
    
    // Управление доверием
    bool requestDeviceTrust(const std::string& device_id, const std::string& proof_signature);
    std::string createTrustProof(const std::string& device_id);
    bool verifyTrustProof(const std::string& device_id, const std::string& proof);
    
    // Утилиты
    std::string getDeviceFingerprint(const std::string& device_id);
    bool isLocalDevice(const std::string& device_id) const { return device_id == local_device_id; }
};

#endif // AUTH_H