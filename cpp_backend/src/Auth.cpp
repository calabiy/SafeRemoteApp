#include "Auth.h"
#include <iostream>
#include <fstream>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

Auth::Auth(const std::string& config_path) : config_file(config_path) {
    loadConfig();
    
    // Если нет локального устройства, создаем его
    if (local_device_id.empty()) {
        std::string hostname = "default_device_" + std::to_string(getCurrentTimestamp());
        generateLocalKeys(hostname, hostname);
    }
}

Auth::~Auth() {
    saveConfig();
}

bool Auth::registerDevice(const std::string& device_id, const std::string& device_name, 
                         const std::string& public_key) {
    DeviceInfo device;
    device.device_id = device_id;
    device.device_name = device_name;
    device.public_key = public_key;
    device.trusted = false;
    device.last_seen = getCurrentTimestamp();
    device.created_at = device.last_seen;
    device.fingerprint = calculateFingerprint(public_key);
    
    devices[device_id] = device;
    saveConfig();
    
    std::cout << "Device registered: " << device_name << " (" << device_id << ")" << std::endl;
    std::cout << "Fingerprint: " << device.fingerprint << std::endl;
    return true;
}

bool Auth::trustDevice(const std::string& device_id) {
    auto it = devices.find(device_id);
    if (it != devices.end()) {
        it->second.trusted = true;
        it->second.last_seen = getCurrentTimestamp();
        saveConfig();
        std::cout << "Device trusted: " << it->second.device_name << std::endl;
        return true;
    }
    return false;
}

bool Auth::revokeDevice(const std::string& device_id) {
    auto it = devices.find(device_id);
    if (it != devices.end()) {
        it->second.trusted = false;
        // Завершаем все активные сессии этого устройства
        for (auto& session : active_sessions) {
            if (session.second.requester_id == device_id) {
                session.second.status = SessionStatus::REVOKED;
            }
        }
        saveConfig();
        std::cout << "Device revoked: " << it->second.device_name << std::endl;
        return true;
    }
    return false;
}

bool Auth::isDeviceTrusted(const std::string& device_id) {
    auto it = devices.find(device_id);
    if (it != devices.end()) {
        return it->second.trusted;
    }
    return false;
}

std::string Auth::createSession(const std::string& requester_id, const std::string& host_id,
                              const std::string& permissions) {
    std::string session_id = generateSessionId();
    
    Session session;
    session.session_id = session_id;
    session.requester_id = requester_id;
    session.host_id = host_id;
    session.permissions = permissions;
    session.status = SessionStatus::PENDING;
    session.created_at = getCurrentTimestamp();
    session.last_activity = session.created_at;
    session.expires_at = session.created_at + SESSION_TIMEOUT;
    session.challenge = generateChallenge();
    
    active_sessions[session_id] = session;
    
    std::cout << "Session created: " << session_id << std::endl;
    return session_id;
}

bool Auth::authorizeSession(const std::string& session_id, bool approved) {
    auto it = active_sessions.find(session_id);
    if (it != active_sessions.end()) {
        it->second.status = approved ? SessionStatus::ACTIVE : SessionStatus::DENIED;
        it->second.last_activity = getCurrentTimestamp();
        
        if (approved) {
            std::cout << "Session authorized: " << session_id << std::endl;
        } else {
            std::cout << "Session denied: " << session_id << std::endl;
        }
        
        return true;
    }
    return false;
}

bool Auth::validateSession(const std::string& session_id) {
    auto it = active_sessions.find(session_id);
    if (it != active_sessions.end()) {
        Session& session = it->second;
        
        // Проверка статуса
        if (session.status != SessionStatus::ACTIVE) {
            return false;
        }
        
        // Проверка истечения времени
        uint64_t now = getCurrentTimestamp();
        if (now > session.expires_at) {
            session.status = SessionStatus::EXPIRED;
            return false;
        }
        
        // Проверка доверия устройства
        if (!isDeviceTrusted(session.requester_id)) {
            session.status = SessionStatus::REVOKED;
            return false;
        }
        
        // Обновление активности
        session.last_activity = now;
        return true;
    }
    return false;
}

void Auth::terminateSession(const std::string& session_id) {
    auto it = active_sessions.find(session_id);
    if (it != active_sessions.end()) {
        it->second.status = SessionStatus::TERMINATED;
        std::cout << "Session terminated: " << session_id << std::endl;
    }
}

std::vector<DeviceInfo> Auth::getDevices() const {
    std::vector<DeviceInfo> result;
    for (const auto& device : devices) {
        result.push_back(device.second);
    }
    return result;
}

std::vector<Session> Auth::getActiveSessions() const {
    std::vector<Session> result;
    for (const auto& session : active_sessions) {
        if (session.second.status == SessionStatus::ACTIVE) {
            result.push_back(session.second);
        }
    }
    return result;
}

void Auth::cleanupExpiredSessions() {
    uint64_t now = getCurrentTimestamp();
    auto it = active_sessions.begin();
    
    while (it != active_sessions.end()) {
        if (now > it->second.expires_at || 
            it->second.status == SessionStatus::TERMINATED ||
            it->second.status == SessionStatus::DENIED) {
            it = active_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

bool Auth::hasPermission(const std::string& session_id, const std::string& permission) {
    auto it = active_sessions.find(session_id);
    if (it != active_sessions.end()) {
        // Простая проверка разрешений (можно расширить)
        return it->second.permissions == "full" || 
               it->second.permissions.find(permission) != std::string::npos;
    }
    return false;
}

// Новые криптографические методы

KeyPair Auth::generateKeyPair() {
    KeyPair keypair;
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Failed to create key context" << std::endl;
        return keypair;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Failed to initialize key generation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return keypair;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
        std::cerr << "Failed to set key size" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return keypair;
    }
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Failed to generate key pair" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return keypair;
    }
    
    // Экспорт публичного ключа
    BIO* pub_bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PUBKEY(pub_bio, pkey)) {
        char* pub_key_data;
        long pub_key_len = BIO_get_mem_data(pub_bio, &pub_key_data);
        keypair.public_key = std::string(pub_key_data, pub_key_len);
    }
    BIO_free(pub_bio);
    
    // Экспорт приватного ключа
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        char* priv_key_data;
        long priv_key_len = BIO_get_mem_data(priv_bio, &priv_key_data);
        keypair.private_key = std::string(priv_key_data, priv_key_len);
    }
    BIO_free(priv_bio);
    
    keypair.fingerprint = calculateFingerprint(keypair.public_key);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return keypair;
}

KeyPair Auth::generateLocalKeys(const std::string& device_id, const std::string& device_name) {
    local_keys = generateKeyPair();
    local_device_id = device_id;
    
    // Регистрируем локальное устройство
    DeviceInfo local_device;
    local_device.device_id = device_id;
    local_device.device_name = device_name;
    local_device.public_key = local_keys.public_key;
    local_device.private_key = local_keys.private_key;
    local_device.trusted = true; // Локальное устройство доверенное по умолчанию
    local_device.last_seen = getCurrentTimestamp();
    local_device.created_at = local_device.last_seen;
    local_device.fingerprint = local_keys.fingerprint;
    
    devices[device_id] = local_device;
    saveConfig();
    
    std::cout << "Local device keys generated for: " << device_name << std::endl;
    std::cout << "Device ID: " << device_id << std::endl;
    std::cout << "Fingerprint: " << local_keys.fingerprint << std::endl;
    
    return local_keys;
}

std::string Auth::signData(const std::string& data, const std::string& private_key) {
    EVP_PKEY* pkey = loadPrivateKeyFromPEM(private_key);
    if (!pkey) {
        return "";
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }
    
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    if (EVP_DigestSignUpdate(ctx, data.c_str(), data.length()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    size_t sig_len;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    unsigned char* sig = new unsigned char[sig_len];
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) {
        delete[] sig;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // Конвертируем в Base64 или hex
    std::string result;
    result.reserve(sig_len * 2);
    for (size_t i = 0; i < sig_len; ++i) {
        char hex[3];
        sprintf(hex, "%02x", sig[i]);
        result += hex;
    }
    
    delete[] sig;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return result;
}

bool Auth::verifySignature(const std::string& data, const std::string& signature, 
                          const std::string& public_key) {
    EVP_PKEY* pkey = loadPublicKeyFromPEM(public_key);
    if (!pkey) {
        return false;
    }
    
    // Конвертируем hex signature обратно в байты
    std::vector<unsigned char> sig_bytes;
    sig_bytes.reserve(signature.length() / 2);
    for (size_t i = 0; i < signature.length(); i += 2) {
        unsigned int byte;
        sscanf(signature.substr(i, 2).c_str(), "%02x", &byte);
        sig_bytes.push_back(static_cast<unsigned char>(byte));
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (EVP_DigestVerifyUpdate(ctx, data.c_str(), data.length()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    int result = EVP_DigestVerifyFinal(ctx, sig_bytes.data(), sig_bytes.size());
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return result == 1;
}

std::string Auth::createAuthChallenge(const std::string& session_id) {
    auto it = active_sessions.find(session_id);
    if (it != active_sessions.end()) {
        it->second.challenge = generateChallenge();
        return it->second.challenge;
    }
    return "";
}

bool Auth::verifyAuthChallenge(const std::string& session_id, const std::string& signature) {
    auto it = active_sessions.find(session_id);
    if (it != active_sessions.end()) {
        const Session& session = it->second;
        auto device_it = devices.find(session.requester_id);
        if (device_it != devices.end()) {
            bool verified = verifySignature(session.challenge, signature, device_it->second.public_key);
            if (verified) {
                it->second.signature = signature;
                it->second.status = SessionStatus::ACTIVE;
                std::cout << "Auth challenge verified for session: " << session_id << std::endl;
            }
            return verified;
        }
    }
    return false;
}

bool Auth::requestDeviceTrust(const std::string& device_id, const std::string& proof_signature) {
    auto it = devices.find(device_id);
    if (it != devices.end() && !it->second.trusted) {
        // Создаем proof данные для верификации
        std::string proof_data = device_id + ":" + std::to_string(getCurrentTimestamp());
        if (verifySignature(proof_data, proof_signature, it->second.public_key)) {
            std::cout << "Trust request received from: " << it->second.device_name << std::endl;
            std::cout << "Approve trust for device? (Manual approval required)" << std::endl;
            return true;
        }
    }
    return false;
}

std::string Auth::createTrustProof(const std::string& device_id) {
    if (device_id == local_device_id) {
        std::string proof_data = device_id + ":" + std::to_string(getCurrentTimestamp());
        return signData(proof_data, local_keys.private_key);
    }
    return "";
}

bool Auth::verifyTrustProof(const std::string& device_id, const std::string& proof) {
    auto it = devices.find(device_id);
    if (it != devices.end()) {
        std::string proof_data = device_id + ":" + std::to_string(getCurrentTimestamp());
        return verifySignature(proof_data, proof, it->second.public_key);
    }
    return false;
}

std::string Auth::getDeviceFingerprint(const std::string& device_id) {
    auto it = devices.find(device_id);
    if (it != devices.end()) {
        return it->second.fingerprint;
    }
    return "";
}

// Внутренние вспомогательные методы

std::string Auth::generateSessionId() {
    // Криптографически стойкий генератор
    unsigned char bytes[32];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        // Fallback на более простой генератор
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (int i = 0; i < 32; ++i) {
            bytes[i] = dis(gen);
        }
    }
    
    // Конвертация в hex строку
    std::string result;
    result.reserve(64);
    for (int i = 0; i < 32; ++i) {
        char hex[3];
        sprintf(hex, "%02x", bytes[i]);
        result += hex;
    }
    
    return result;
}

std::string Auth::generateChallenge() {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (int i = 0; i < 16; ++i) {
            bytes[i] = dis(gen);
        }
    }
    
    std::string result;
    result.reserve(32);
    for (int i = 0; i < 16; ++i) {
        char hex[3];
        sprintf(hex, "%02x", bytes[i]);
        result += hex;
    }
    
    return result;
}

uint64_t Auth::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

EVP_PKEY* Auth::loadPublicKeyFromPEM(const std::string& pem_key) {
    BIO* bio = BIO_new_mem_buf(pem_key.data(), pem_key.length());
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

EVP_PKEY* Auth::loadPrivateKeyFromPEM(const std::string& pem_key) {
    BIO* bio = BIO_new_mem_buf(pem_key.data(), pem_key.length());
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

std::string Auth::calculateFingerprint(const std::string& public_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(public_key.c_str()), 
           public_key.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        if (i < SHA256_DIGEST_LENGTH - 1 && i % 2 == 1) {
            ss << ":";
        }
    }
    
    return ss.str();
}

void Auth::loadConfig() {
    std::ifstream file(config_file);
    if (!file.is_open()) {
        std::cout << "No config file found, creating new one" << std::endl;
        return;
    }
    
    Json::Value root;
    file >> root;
    
    // Загрузка локального устройства
    if (root.isMember("local_device")) {
        const Json::Value& local = root["local_device"];
        local_device_id = local["device_id"].asString();
        local_keys.public_key = local["public_key"].asString();
        local_keys.private_key = local["private_key"].asString();
        local_keys.fingerprint = local["fingerprint"].asString();
    }
    
    // Загрузка устройств
    if (root.isMember("devices")) {
        for (const auto& device_data : root["devices"]) {
            DeviceInfo device;
            device.device_id = device_data["device_id"].asString();
            device.device_name = device_data["device_name"].asString();
            device.public_key = device_data["public_key"].asString();
            device.trusted = device_data["trusted"].asBool();
            device.last_seen = device_data["last_seen"].asUInt64();
            device.created_at = device_data["created_at"].asUInt64();
            device.fingerprint = device_data["fingerprint"].asString();
            
            // Приватный ключ только для локального устройства
            if (device_data.isMember("private_key")) {
                device.private_key = device_data["private_key"].asString();
            }
            
            devices[device.device_id] = device;
        }
    }
    
    file.close();
    std::cout << "Config loaded: " << devices.size() << " devices" << std::endl;
}

void Auth::saveConfig() {
    Json::Value root;
    
    // Сохранение локального устройства
    if (!local_device_id.empty()) {
        Json::Value local;
        local["device_id"] = local_device_id;
        local["public_key"] = local_keys.public_key;
        local["private_key"] = local_keys.private_key;
        local["fingerprint"] = local_keys.fingerprint;
        root["local_device"] = local;
    }
    
    Json::Value devices_array(Json::arrayValue);
    
    for (const auto& device : devices) {
        Json::Value device_data;
        device_data["device_id"] = device.second.device_id;
        device_data["device_name"] = device.second.device_name;
        device_data["public_key"] = device.second.public_key;
        device_data["trusted"] = device.second.trusted;
        device_data["last_seen"] = device.second.last_seen;
        device_data["created_at"] = device.second.created_at;
        device_data["fingerprint"] = device.second.fingerprint;
        
        // Приватный ключ только для локального устройства
        if (!device.second.private_key.empty()) {
            device_data["private_key"] = device.second.private_key;
        }
        
        devices_array.append(device_data);
    }
    
    root["devices"] = devices_array;
    
    std::ofstream file(config_file);
    if (file.is_open()) {
        file << root;
        file.close();
        std::cout << "Config saved" << std::endl;
    } else {
        std::cerr << "Failed to save config" << std::endl;
    }