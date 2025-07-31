#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <chrono>
#include <cstdint>

// Структуры для системной информации
struct SystemInfo {
    std::string os_name;
    std::string os_version;
    std::string architecture;
    std::string hostname;
    std::string username;
    uint64_t total_memory;
    uint64_t available_memory;
    double cpu_usage;
    std::string device_model;
    std::string android_version; // Для Android
};

struct NetworkInterface {
    std::string name;
    std::string ip_address;
    std::string mac_address;
    std::string netmask;
    bool is_up;
    bool is_wireless;
};

struct NetworkInfo {
    std::vector<NetworkInterface> interfaces;
    std::string default_gateway;
    std::string external_ip;
    std::vector<std::string> dns_servers;
};

struct ScreenInfo {
    int width;
    int height;
    int bits_per_pixel;
    double refresh_rate;
    int dpi;
    std::string orientation; // portrait, landscape
};

// Перечисления
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

enum class FilePermission {
    READ = 1,
    WRITE = 2,
    EXECUTE = 4
};

class Utils {
public:
    // ===== СИСТЕМНАЯ ИНФОРМАЦИЯ =====
    static SystemInfo getSystemInfo();
    static NetworkInfo getNetworkInfo();
    static ScreenInfo getScreenInfo();
    static std::string getDeviceId();
    static std::string getHostname();
    static std::string getCurrentUser();
    static std::string getHomeDirectory();
    static std::string getTempDirectory();
    static std::vector<std::string> getRunningProcesses();
    static bool isProcessRunning(const std::string& processName);
    
    // ===== ВРЕМЯ И ДАТА =====
    static uint64_t getCurrentTimestamp();
    static std::string getCurrentTimeString(const std::string& format = "%Y-%m-%d %H:%M:%S");
    static std::string timestampToString(uint64_t timestamp, const std::string& format = "%Y-%m-%d %H:%M:%S");
    static uint64_t stringToTimestamp(const std::string& timeStr, const std::string& format = "%Y-%m-%d %H:%M:%S");
    static void sleep(int milliseconds);
    static uint64_t getMSTimestamp(); // Миллисекунды
    
    // ===== ФАЙЛОВАЯ СИСТЕМА =====
    static bool fileExists(const std::string& path);
    static bool directoryExists(const std::string& path);
    static bool createDirectory(const std::string& path, bool recursive = true);
    static bool deleteFile(const std::string& path);
    static bool deleteDirectory(const std::string& path, bool recursive = true);
    static std::vector<std::string> listDirectory(const std::string& path);
    static uint64_t getFileSize(const std::string& path);
    static std::string getFileExtension(const std::string& path);
    static std::string getFileName(const std::string& path);
    static std::string getDirectoryName(const std::string& path);
    static std::string joinPath(const std::string& path1, const std::string& path2);
    static std::string getAbsolutePath(const std::string& path);
    static bool copyFile(const std::string& source, const std::string& destination);
    static bool moveFile(const std::string& source, const std::string& destination);
    static int getFilePermissions(const std::string& path);
    static bool setFilePermissions(const std::string& path, int permissions);
    
    // ===== СТРОКОВЫЕ УТИЛИТЫ =====
    static std::string trim(const std::string& str);
    static std::string toLowerCase(const std::string& str);
    static std::string toUpperCase(const std::string& str);
    static std::vector<std::string> split(const std::string& str, const std::string& delimiter);
    static std::string join(const std::vector<std::string>& strings, const std::string& delimiter);
    static bool startsWith(const std::string& str, const std::string& prefix);
    static bool endsWith(const std::string& str, const std::string& suffix);
    static std::string replace(const std::string& str, const std::string& from, const std::string& to);
    static std::string urlEncode(const std::string& str);
    static std::string urlDecode(const std::string& str);
    static bool isValidIP(const std::string& ip);
    static bool isValidEmail(const std::string& email);
    
    // ===== КОДИРОВАНИЕ И КРИПТОГРАФИЯ =====
    static std::string base64Encode(const std::string& data);
    static std::string base64Decode(const std::string& encoded);
    static std::string hexEncode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> hexDecode(const std::string& hex);
    static std::string generateRandomString(int length, bool alphanumeric = true);
    static std::string generateUUID();
    static std::string calculateMD5(const std::string& data);
    static std::string calculateSHA256(const std::string& data);
    static std::string calculateFileHash(const std::string& filePath, const std::string& algorithm = "sha256");
    
    // ===== СЕТЕВЫЕ УТИЛИТЫ =====
    static bool isPortOpen(const std::string& host, int port, int timeoutMs = 5000);
    static bool isInternetAvailable();
    static std::string resolveHostname(const std::string& hostname);
    static std::vector<std::string> getLocalIPs();
    static std::string getExternalIP();
    static std::string getMacAddress(const std::string& interface = "");
    static int getAvailablePort(int startPort = 8000);
    static bool isValidPort(int port);
    static std::string formatBytes(uint64_t bytes);
    
    // ===== ПРОЦЕССЫ И КОМАНДЫ =====
    static std::string executeCommand(const std::string& command);
    static int executeCommandWithCode(const std::string& command, std::string& output);
    static bool killProcess(const std::string& processName);
    static bool killProcess(int pid);
    static std::vector<int> findProcessesByName(const std::string& name);
    static std::string getProcessName(int pid);
    static std::map<std::string, std::string> getEnvironmentVariables();
    static std::string getEnvironmentVariable(const std::string& name, const std::string& defaultValue = "");
    static bool setEnvironmentVariable(const std::string& name, const std::string& value);
    
    // ===== JSON УТИЛИТЫ =====
    static std::string jsonEscape(const std::string& str);
    static bool isValidJson(const std::string& json);
    static std::string formatJson(const std::string& json, bool prettyPrint = true);
    
    // ===== ЛОГИРОВАНИЕ =====
    static void setLogLevel(LogLevel level);
    static void setLogFile(const std::string& filePath);
    static void log(LogLevel level, const std::string& message, const std::string& category = "");
    static void logDebug(const std::string& message, const std::string& category = "");
    static void logInfo(const std::string& message, const std::string& category = "");
    static void logWarning(const std::string& message, const std::string& category = "");
    static void logError(const std::string& message, const std::string& category = "");
    static void logCritical(const std::string& message, const std::string& category = "");
    
    // ===== КОНФИГУРАЦИЯ =====
    static bool loadConfig(const std::string& filePath, std::map<std::string, std::string>& config);
    static bool saveConfig(const std::string& filePath, const std::map<std::string, std::string>& config);
    static std::string getConfigValue(const std::map<std::string, std::string>& config, 
                                     const std::string& key, const std::string& defaultValue = "");
    
    // ===== ANDROID СПЕЦИФИЧНЫЕ =====
#ifdef __ANDROID__
    static std::string getAndroidId();
    static std::string getAndroidVersion();
    static std::string getDeviceModel();
    static std::string getManufacturer();
    static int getSDKVersion();
    static std::string getPackageName();
    static bool hasPermission(const std::string& permission);
    static std::string getInternalStoragePath();
    static std::string getExternalStoragePath();
    static bool isRooted();
    static int getBatteryLevel();
    static bool isCharging();
#endif
    
    // ===== ВАЛИДАЦИЯ И БЕЗОПАСНОСТЬ =====
    static bool isValidDeviceId(const std::string& deviceId);
    static bool isSecurePassword(const std::string& password);
    static std::string sanitizeInput(const std::string& input);
    static bool isPathTraversalAttempt(const std::string& path);
    static std::string escapeShellCommand(const std::string& command);
    
    // ===== ПРОИЗВОДИТЕЛЬНОСТЬ =====
    static double getCPUUsage();
    static uint64_t getMemoryUsage(); // Bytes
    static uint64_t getDiskUsage(const std::string& path); // Bytes
    static uint64_t getDiskFree(const std::string& path); // Bytes
    static std::string getSystemLoad();
    
    // ===== КОЛБЭКИ И СОБЫТИЯ =====
    using EventCallback = std::function<void(const std::string&, const std::map<std::string, std::string>&)>;
    static void addEventListener(const std::string& eventType, EventCallback callback);
    static void removeEventListener(const std::string& eventType);
    static void triggerEvent(const std::string& eventType, const std::map<std::string, std::string>& data);
    
private:
    // Внутренние утилиты
    static std::string getCurrentTimeStringInternal(const std::string& format);
    static void writeLog(LogLevel level, const std::string& message, const std::string& category);
    static std::string logLevelToString(LogLevel level);
    static bool initializeNetworking();
    static void cleanupNetworking();
    
    // Статические переменные для конфигурации
    static LogLevel current_log_level;
    static std::string log_file_path;
    static std::map<std::string, EventCallback> event_listeners;
    static bool networking_initialized;
};

// Удобные макросы для логирования
#define LOG_DEBUG(msg) Utils::logDebug(msg, __FUNCTION__)
#define LOG_INFO(msg) Utils::logInfo(msg, __FUNCTION__)
#define LOG_WARNING(msg) Utils::logWarning(msg, __FUNCTION__)
#define LOG_ERROR(msg) Utils::logError(msg, __FUNCTION__)
#define LOG_CRITICAL(msg) Utils::logCritical(msg, __FUNCTION__)

// Макросы для Android логирования
#ifdef __ANDROID__
#define ANDROID_LOG_DEBUG(msg) __android_log_print(ANDROID_LOG_DEBUG, "RemoteAccess", "%s", msg)
#define ANDROID_LOG_INFO(msg) __android_log_print(ANDROID_LOG_INFO, "RemoteAccess", "%s", msg)
#define ANDROID_LOG_WARN(msg) __android_log_print(ANDROID_LOG_WARN, "RemoteAccess", "%s", msg)
#define ANDROID_LOG_ERROR(msg) __android_log_print(ANDROID_LOG_ERROR, "RemoteAccess", "%s", msg)
#endif

#endif // UTILS_HPP