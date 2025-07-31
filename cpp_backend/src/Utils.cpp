#include "Utils.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <random>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <chrono>
#include <filesystem>

// Платформенно-зависимые заголовки
#ifdef __ANDROID__
    #include <android/log.h>
    #include <sys/system_properties.h>
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <ifaddrs.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <sys/statvfs.h>
    #include <sys/sysinfo.h>
#elif defined(_WIN32)
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <shlobj.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #include <shellapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "shell32.lib")
#else
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <sys/statvfs.h>
    #include <sys/sysinfo.h>
    #include <pwd.h>
    #include <dirent.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
#endif

// OpenSSL для криптографических функций
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Инициализация статических переменных
LogLevel Utils::current_log_level = LogLevel::INFO;
std::string Utils::log_file_path = "";
std::map<std::string, Utils::EventCallback> Utils::event_listeners;
bool Utils::networking_initialized = false;

// ===== СИСТЕМНАЯ ИНФОРМАЦИЯ =====

SystemInfo Utils::getSystemInfo() {
    SystemInfo info;
    
#ifdef __ANDROID__
    struct utsname uts;
    if (uname(&uts) == 0) {
        info.os_name = "Android";
        info.architecture = uts.machine;
        info.hostname = uts.nodename;
    }
    
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.release", prop_value) > 0) {
        info.android_version = prop_value;
        info.os_version = "Android " + info.android_version;
    }
    
    if (__system_property_get("ro.product.model", prop_value) > 0) {
        info.device_model = prop_value;
    }
    
    // Информация о памяти
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_memory = si.totalram * si.mem_unit;
        info.available_memory = si.freeram * si.mem_unit;
    }
    
#elif defined(_WIN32)
    info.os_name = "Windows";
    
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    info.os_version = std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            info.architecture = "x64";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            info.architecture = "x86";
            break;
        default:
            info.architecture = "unknown";
            break;
    }
    
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        info.hostname = computerName;
    }
    
    char userName[256];
    size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        info.username = userName;
    }
    
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        info.total_memory = memInfo.ullTotalPhys;
        info.available_memory = memInfo.ullAvailPhys;
    }
    
#else
    struct utsname uts;
    if (uname(&uts) == 0) {
        info.os_name = uts.sysname;
        info.os_version = uts.release;
        info.architecture = uts.machine;
        info.hostname = uts.nodename;
    }
    
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        info.username = pw->pw_name;
    }
    
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_memory = si.totalram * si.mem_unit;
        info.available_memory = si.freeram * si.mem_unit;
    }
#endif
    
    info.cpu_usage = getCPUUsage();
    
    return info;
}

NetworkInfo Utils::getNetworkInfo() {
    NetworkInfo netInfo;
    
#ifdef _WIN32
    // Windows реализация
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            NetworkInterface iface;
            iface.name = pAdapter->AdapterName;
            iface.ip_address = pAdapter->IpAddressList.IpAddress.String;
            iface.netmask = pAdapter->IpAddressList.IpMask.String;
            
            // MAC адрес
            std::stringstream ss;
            for (int i = 0; i < pAdapter->AddressLength; i++) {
                if (i > 0) ss << ":";
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapter->Address[i];
            }
            iface.mac_address = ss.str();
            
            iface.is_up = true; // Упрощение
            iface.is_wireless = (pAdapter->Type == IF_TYPE_IEEE80211);
            
            netInfo.interfaces.push_back(iface);
            pAdapter = pAdapter->Next;
        }
    }
    
    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
    
#else
    // Linux/Android реализация
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return netInfo;
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            NetworkInterface iface;
            iface.name = ifa->ifa_name;
            
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            iface.ip_address = inet_ntoa(addr_in->sin_addr);
            
            if (ifa->ifa_netmask) {
                struct sockaddr_in* mask_in = (struct sockaddr_in*)ifa->ifa_netmask;
                iface.netmask = inet_ntoa(mask_in->sin_addr);
            }
            
            iface.is_up = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
            iface.is_wireless = false; // Упрощение
            
            // MAC адрес получить сложнее, пока пропускаем
            iface.mac_address = getMacAddress(iface.name);
            
            netInfo.interfaces.push_back(iface);
        }
    }
    
    freeifaddrs(ifaddr);
#endif
    
    netInfo.external_ip = getExternalIP();
    
    return netInfo;
}

ScreenInfo Utils::getScreenInfo() {
    ScreenInfo screenInfo;
    
#ifdef _WIN32
    screenInfo.width = GetSystemMetrics(SM_CXSCREEN);
    screenInfo.height = GetSystemMetrics(SM_CYSCREEN);
    screenInfo.bits_per_pixel = GetDeviceCaps(GetDC(NULL), BITSPIXEL);
    screenInfo.dpi = GetDeviceCaps(GetDC(NULL), LOGPIXELSX);
    screenInfo.refresh_rate = 60.0; // Упрощение
    screenInfo.orientation = (screenInfo.width > screenInfo.height) ? "landscape" : "portrait";
    
#elif defined(__ANDROID__)
    // На Android это нужно получать через JNI
    screenInfo.width = 1920; // Заглушка
    screenInfo.height = 1080;
    screenInfo.bits_per_pixel = 24;
    screenInfo.dpi = 160;
    screenInfo.refresh_rate = 60.0;
    screenInfo.orientation = "landscape";
    
#else
    // Linux - нужен X11 или Wayland
    screenInfo.width = 1920; // Заглушка
    screenInfo.height = 1080;
    screenInfo.bits_per_pixel = 24;
    screenInfo.dpi = 96;
    screenInfo.refresh_rate = 60.0;
    screenInfo.orientation = "landscape";
#endif
    
    return screenInfo;
}

std::string Utils::getDeviceId() {
#ifdef __ANDROID__
    return getAndroidId();
#elif defined(_WIN32)
    // Используем MAC адрес как device ID
    std::string mac = getMacAddress();
    if (!mac.empty()) {
        return "WIN_" + mac;
    }
    return "WIN_" + generateRandomString(16);
#else
    // Linux - используем hostname + MAC
    std::string hostname = getHostname();
    std::string mac = getMacAddress();
    return "LINUX_" + hostname + "_" + mac;
#endif
}

std::string Utils::getHostname() {
#ifdef _WIN32
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        return std::string(computerName);
    }
    return "unknown";
#else
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
#endif
}

std::string Utils::getCurrentUser() {
#ifdef _WIN32
    char userName[256];
    DWORD size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        return std::string(userName);
    }
    return "unknown";
#else
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "unknown";
#endif
}

// ===== ВРЕМЯ И ДАТА =====

uint64_t Utils::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

uint64_t Utils::getMSTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string Utils::getCurrentTimeString(const std::string& format) {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&time);
    
    std::stringstream ss;
    ss << std::put_time(tm, format.c_str());
    return ss.str();
}

void Utils::sleep(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

// ===== ФАЙЛОВАЯ СИСТЕМА =====

bool Utils::fileExists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

bool Utils::directoryExists(const std::string& path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool Utils::createDirectory(const std::string& path, bool recursive) {
    if (recursive) {
        return std::filesystem::create_directories(path);
    } else {
        return std::filesystem::create_directory(path);
    }
}

std::vector<std::string> Utils::listDirectory(const std::string& path) {
    std::vector<std::string> files;
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            files.push_back(entry.path().filename().string());
        }
    } catch (const std::exception& e) {
        logError("Failed to list directory: " + std::string(e.what()));
    }
    
    return files;
}

uint64_t Utils::getFileSize(const std::string& path) {
    try {
        return std::filesystem::file_size(path);
    } catch (const std::exception&) {
        return 0;
    }
}

std::string Utils::getFileExtension(const std::string& path) {
    std::filesystem::path p(path);
    return p.extension().string();
}

std::string Utils::getFileName(const std::string& path) {
    std::filesystem::path p(path);
    return p.filename().string();
}

std::string Utils::getDirectoryName(const std::string& path) {
    std::filesystem::path p(path);
    return p.parent_path().string();
}

std::string Utils::joinPath(const std::string& path1, const std::string& path2) {
    std::filesystem::path p1(path1);
    std::filesystem::path p2(path2);
    return (p1 / p2).string();
}

// ===== СТРОКОВЫЕ УТИЛИТЫ =====

std::string Utils::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

std::string Utils::toLowerCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string Utils::toUpperCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::vector<std::string> Utils::split(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);
    
    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    
    tokens.push_back(str.substr(start));
    return tokens;
}

std::string Utils::join(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) return "";
    
    std::stringstream ss;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i > 0) ss << delimiter;
        ss << strings[i];
    }
    return ss.str();
}

bool Utils::startsWith(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

bool Utils::endsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool Utils::isValidIP(const std::string& ip) {
    std::regex ipRegex(R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
    return std::regex_match(ip, ipRegex);
}

bool Utils::isValidEmail(const std::string& email) {
    std::regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return std::regex_match(email, emailRegex);
}

// ===== КОДИРОВАНИЕ И КРИПТОГРАФИЯ =====

std::string Utils::base64Encode(const std::string& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.c_str(), data.length());
    BIO_flush(bio);
    
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    
    return result;
}

std::string Utils::base64Decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.c_str(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    char* buffer = new char[encoded.length()];
    int decodedLength = BIO_read(bio, buffer, encoded.length());
    
    std::string result(buffer, decodedLength);
    delete[] buffer;
    BIO_free_all(bio);
    
    return result;
}

std::string Utils::hexEncode(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> Utils::hexDecode(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string Utils::generateRandomString(int length, bool alphanumeric) {
    const std::string chars = alphanumeric ? 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" :
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += chars[dis(gen)];
    }
    
    return result;
}

std::string Utils::generateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);
    
    std::stringstream ss;
    ss << std::hex;
    
    for (int i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    
    for (int i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";
    
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    
    ss << dis2(gen);
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    
    for (int i = 0; i < 12; i++) {
        ss << dis(gen);
    }
    
    return ss.str();
}

std::string Utils::calculateMD5(const std::string& data) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

std::string Utils::calculateSHA256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

// ===== СЕТЕВЫЕ УТИЛИТЫ =====

bool Utils::isPortOpen(const std::string& host, int port, int timeoutMs) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
        // Если не IP адрес, пробуем разрешить hostname
        struct hostent* he = gethostbyname(host.c_str());
        if (he == nullptr) {
#ifdef _WIN32
            closesocket(sock);
            WSACleanup();
#else
            close(sock);
#endif
            return false;
        }
        memcpy(&serv_addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    // Устанавливаем таймаут
#ifdef _WIN32
    DWORD timeout = timeoutMs;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    
    int result = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    
    return result == 0;
}

bool Utils::isInternetAvailable() {
    return isPortOpen("8.8.8.8", 53, 3000) || isPortOpen("1.1.1.1", 53, 3000);
}

std::vector<std::string> Utils::getLocalIPs() {
    std::vector<std::string> ips;
    NetworkInfo netInfo = getNetworkInfo();
    
    for (const auto& iface : netInfo.interfaces) {
        if (iface.is_up && iface.ip_address != "127.0.0.1" && !iface.ip_address.empty()) {
            ips.push_back(iface.ip_address);
        }
    }
    
    return ips;
}

std::string Utils::getExternalIP() {
    // Простая реализация через HTTP запрос к внешнему сервису
    // В реальном приложении лучше использовать HTTP клиент
    std::string command;
    
#ifdef _WIN32
    command = "curl -s ifconfig.me 2>nul";
#else
    command = "curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null";
#endif
    
    std::string result = executeCommand(command);
    result = trim(result);
    
    if (isValidIP(result)) {
        return result;
    }
    
    return "";
}

std::string Utils::getMacAddress(const std::string& interface) {
#ifdef _WIN32
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    
    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        
        std::stringstream ss;
        for (int i = 0; i < pAdapterInfo->AddressLength; i++) {
            if (i > 0) ss << ":";
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapterInfo->Address[i];
        }
        return ss.str();
    }
#else
    // Linux/Android реализация
    std::string path = "/sys/class/net/" + (interface.empty() ? "eth0" : interface) + "/address";
    std::ifstream file(path);
    if (file.is_open()) {
        std::string mac;
        std::getline(file, mac);
        return trim(mac);
    }
    
    // Альтернативный способ через ifconfig
    if (interface.empty()) {
        std::string command = "cat /sys/class/net/*/address | head -1";
        std::string result = executeCommand(command);
        return trim(result);
    }
#endif
    
    return "";
}

int Utils::getAvailablePort(int startPort) {
    for (int port = startPort; port < 65535; ++port) {
        if (!isPortOpen("127.0.0.1", port, 100)) {
            return port;
        }
    }
    return -1;
}

bool Utils::isValidPort(int port) {
    return port > 0 && port <= 65535;
}

std::string Utils::formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return ss.str();
}

// ===== ПРОЦЕССЫ И КОМАНДЫ =====

std::string Utils::executeCommand(const std::string& command) {
    std::string output;
    executeCommandWithCode(command, output);
    return output;
}

int Utils::executeCommandWithCode(const std::string& command, std::string& output) {
    output.clear();
    
#ifdef _WIN32
    HANDLE hPipeRead, hPipeWrite;
    SECURITY_ATTRIBUTES saAttr = {sizeof(SECURITY_ATTRIBUTES)};
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    
    if (!CreatePipe(&hPipeRead, &hPipeWrite, &saAttr, 0)) {
        return -1;
    }
    
    STARTUPINFO si = {sizeof(STARTUPINFO)};
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hPipeWrite;
    si.hStdError = hPipeWrite;
    
    PROCESS_INFORMATION pi;
    
    std::string cmd = "cmd.exe /C " + command;
    if (!CreateProcessA(NULL, const_cast<char*>(cmd.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hPipeWrite);
        CloseHandle(hPipeRead);
        return -1;
    }
    
    CloseHandle(hPipeWrite);
    
    DWORD dwRead;
    CHAR chBuf[4096];
    
    while (ReadFile(hPipeRead, chBuf, 4096, &dwRead, NULL) && dwRead > 0) {
        output.append(chBuf, dwRead);
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hPipeRead);
    
    return static_cast<int>(exitCode);
#else
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return -1;
    }
    
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int exitCode = pclose(pipe);
    return WEXITSTATUS(exitCode);
#endif
}

std::map<std::string, std::string> Utils::getEnvironmentVariables() {
    std::map<std::string, std::string> env;
    
#ifdef _WIN32
    LPCH envStrings = GetEnvironmentStrings();
    if (envStrings) {
        LPTSTR envVar = (LPTSTR)envStrings;
        while (*envVar) {
            std::string var(envVar);
            size_t pos = var.find('=');
            if (pos != std::string::npos) {
                env[var.substr(0, pos)] = var.substr(pos + 1);
            }
            envVar += lstrlen(envVar) + 1;
        }
        FreeEnvironmentStrings(envStrings);
    }
#else
    extern char** environ;
    for (char** env_var = environ; *env_var; ++env_var) {
        std::string var(*env_var);
        size_t pos = var.find('=');
        if (pos != std::string::npos) {
            env[var.substr(0, pos)] = var.substr(pos + 1);
        }
    }
#endif
    
    return env;
}

std::string Utils::getEnvironmentVariable(const std::string& name, const std::string& defaultValue) {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : defaultValue;
}

// ===== ПРОИЗВОДИТЕЛЬНОСТЬ =====

double Utils::getCPUUsage() {
#ifdef _WIN32
    // Windows реализация
    static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
    static int numProcessors;
    static HANDLE self;
    static bool initialized = false;
    
    if (!initialized) {
        SYSTEM_INFO sysInfo;
        FILETIME ftime, fsys, fuser;
        
        GetSystemInfo(&sysInfo);
        numProcessors = sysInfo.dwNumberOfProcessors;
        
        GetSystemTimeAsFileTime(&ftime);
        memcpy(&lastCPU, &ftime, sizeof(FILETIME));
        
        self = GetCurrentProcess();
        GetProcessTimes(self, &ftime, &ftime, &fsys, &fuser);
        memcpy(&lastSysCPU, &fsys, sizeof(FILETIME));
        memcpy(&lastUserCPU, &fuser, sizeof(FILETIME));
        
        initialized = true;
        return 0.0;
    }
    
    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;
    
    GetSystemTimeAsFileTime(&ftime);
    memcpy(&now, &ftime, sizeof(FILETIME));
    
    GetProcessTimes(self, &ftime, &ftime, &fsys, &fuser);
    memcpy(&sys, &fsys, sizeof(FILETIME));
    memcpy(&user, &fuser, sizeof(FILETIME));
    
    double percent = (sys.QuadPart - lastSysCPU.QuadPart) + (user.QuadPart - lastUserCPU.QuadPart);
    percent /= (now.QuadPart - lastCPU.QuadPart);
    percent /= numProcessors;
    
    lastCPU = now;
    lastUserCPU = user;
    lastSysCPU = sys;
    
    return percent * 100.0;
    
#elif defined(__linux__) || defined(__ANDROID__)
    static unsigned long long lastTotalUser, lastTotalUserLow, lastTotalSys, lastTotalIdle;
    static bool initialized = false;
    
    FILE* file = fopen("/proc/stat", "r");
    if (!file) return 0.0;
    
    unsigned long long totalUser, totalUserLow, totalSys, totalIdle, total;
    fscanf(file, "cpu %llu %llu %llu %llu", &totalUser, &totalUserLow, &totalSys, &totalIdle);
    fclose(file);
    
    if (!initialized) {
        lastTotalUser = totalUser;
        lastTotalUserLow = totalUserLow;
        lastTotalSys = totalSys;
        lastTotalIdle = totalIdle;
        initialized = true;
        return 0.0;
    }
    
    total = (totalUser - lastTotalUser) + (totalUserLow - lastTotalUserLow) + (totalSys - lastTotalSys);
    double percent = total;
    total += (totalIdle - lastTotalIdle);
    percent /= total;
    
    lastTotalUser = totalUser;
    lastTotalUserLow = totalUserLow;
    lastTotalSys = totalSys;
    lastTotalIdle = totalIdle;
    
    return percent * 100.0;
#else
    return 0.0;
#endif
}

uint64_t Utils::getMemoryUsage() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
#else
    FILE* file = fopen("/proc/self/status", "r");
    if (!file) return 0;
    
    char line[128];
    while (fgets(line, 128, file) != NULL) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            int kb;
            sscanf(line, "VmRSS: %d kB", &kb);
            fclose(file);
            return kb * 1024; // Конвертируем в байты
        }
    }
    fclose(file);
    return 0;
#endif
}

// ===== ЛОГИРОВАНИЕ =====

void Utils::setLogLevel(LogLevel level) {
    current_log_level = level;
}

void Utils::setLogFile(const std::string& filePath) {
    log_file_path = filePath;
}

void Utils::log(LogLevel level, const std::string& message, const std::string& category) {
    if (level < current_log_level) return;
    
    writeLog(level, message, category);
}

void Utils::logDebug(const std::string& message, const std::string& category) {
    log(LogLevel::DEBUG, message, category);
}

void Utils::logInfo(const std::string& message, const std::string& category) {
    log(LogLevel::INFO, message, category);
}

void Utils::logWarning(const std::string& message, const std::string& category) {
    log(LogLevel::WARNING, message, category);
}

void Utils::logError(const std::string& message, const std::string& category) {
    log(LogLevel::ERROR, message, category);
}

void Utils::logCritical(const std::string& message, const std::string& category) {
    log(LogLevel::CRITICAL, message, category);
}

// ===== ANDROID СПЕЦИФИЧНЫЕ =====

#ifdef __ANDROID__
std::string Utils::getAndroidId() {
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.serialno", prop_value) > 0) {
        return std::string(prop_value);
    }
    return generateRandomString(16);
}

std::string Utils::getAndroidVersion() {
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.release", prop_value) > 0) {
        return std::string(prop_value);
    }
    return "unknown";
}

std::string Utils::getDeviceModel() {
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.product.model", prop_value) > 0) {
        return std::string(prop_value);
    }
    return "unknown";
}

int Utils::getSDKVersion() {
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.sdk", prop_value) > 0) {
        return std::atoi(prop_value);
    }
    return 0;
}
#endif

// ===== ВАЛИДАЦИЯ И БЕЗОПАСНОСТЬ =====

bool Utils::isValidDeviceId(const std::string& deviceId) {
    if (deviceId.empty() || deviceId.length() < 8 || deviceId.length() > 64) {
        return false;
    }
    
    // Проверяем, что состоит только из допустимых символов
    std::regex deviceIdRegex("^[a-zA-Z0-9_-]+$");
    return std::regex_match(deviceId, deviceIdRegex);
}

bool Utils::isSecurePassword(const std::string& password) {
    if (password.length() < 8) return false;
    
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    
    for (char c : password) {
        if (std::isupper(c)) hasUpper = true;
        else if (std::islower(c)) hasLower = true;
        else if (std::isdigit(c)) hasDigit = true;
        else hasSpecial = true;
    }
    
    return hasUpper && hasLower && hasDigit && hasSpecial;
}

std::string Utils::sanitizeInput(const std::string& input) {
    std::string result = input;
    
    // Удаляем опасные символы
    std::string dangerous = "<>\"'&;#include "Utils.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <random>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <chrono>
#include <filesystem>

// Платформенно-зависимые заголовки
#ifdef __ANDROID__
    #include <android/log.h>
    #include <sys/system_properties.h>
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <ifaddrs.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <sys/statvfs.h>
    #include <sys/sysinfo.h>
#elif defined(_WIN32)
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <shlobj.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #include <shellapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "shell32.lib")
#else
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <sys/statvfs.h>
    #include <sys/sysinfo.h>
    #include <pwd.h>
    #include <dirent.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
#endif

// OpenSSL для криптографических функций
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Инициализация статических переменных
LogLevel Utils::current_log_level = LogLevel::INFO;
std::string Utils::log_file_path = "";
std::map<std::string, Utils::EventCallback> Utils::event_listeners;
bool Utils::networking_initialized = false;

// ===== СИСТЕМНАЯ ИНФОРМАЦИЯ =====

SystemInfo Utils::getSystemInfo() {
    SystemInfo info;
    
#ifdef __ANDROID__
    struct utsname uts;
    if (uname(&uts) == 0) {
        info.os_name = "Android";
        info.architecture = uts.machine;
        info.hostname = uts.nodename;
    }
    
    char prop_value[PROP_VALUE_MAX];
    if (__system_property_get("ro.build.version.release", prop_value) > 0) {
        info.android_version = prop_value;
        info.os_version = "Android " + info.android_version;
    }
    
    if (__system_property_get("ro.product.model", prop_value) > 0) {
        info.device_model = prop_value;
    }
    
    // Информация о памяти
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_memory = si.totalram * si.mem_unit;
        info.available_memory = si.freeram * si.mem_unit;
    }
    
#elif defined(_WIN32)
    info.os_name = "Windows";
    
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    info.os_version = std::to_string(osvi.dwMajorVersion) + "." + std::to_string(osvi.dwMinorVersion);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            info.architecture = "x64";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            info.architecture = "x86";
            break;
        default:
            info.architecture = "unknown";
            break;
    }
    
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        info.hostname = computerName;
    }
    
    char userName[256];
    size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        info.username = userName;
    }
    
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        info.total_memory = memInfo.ullTotalPhys;
        info.available_memory = memInfo.ullAvailPhys;
    }
    
#else
    struct utsname uts;
    if (uname(&uts) == 0) {
        info.os_name = uts.sysname;
        info.os_version = uts.release;
        info.architecture = uts.machine;
        info.hostname = uts.nodename;
    }
    
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        info.username = pw->pw_name;
    }
    
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        info.total_memory = si.totalram * si.mem_unit;
        info.available_memory = si.freeram * si.mem_unit;
    }
#endif
    
    info.cpu_usage = getCPUUsage();
    
    return info;
}

NetworkInfo Utils::getNetworkInfo() {
    NetworkInfo netInfo;
    
#ifdef _WIN32
    // Windows реализация
    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(outBufLen);
    }
    
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            NetworkInterface iface;
            iface.name = pAdapter->AdapterName;
            iface.ip_address = pAdapter->IpAddressList.IpAddress.String;
            iface.netmask = pAdapter->IpAddressList.IpMask.String;
            
            // MAC адрес
            std::stringstream ss;
            for (int i = 0; i < pAdapter->AddressLength; i++) {
                if (i > 0) ss << ":";
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapter->Address[i];
            }
            iface.mac_address = ss.str();
            
            iface.is_up = true; // Упрощение
            iface.is_wireless = (pAdapter->Type == IF_TYPE_IEEE80211);
            
            netInfo.interfaces.push_back(iface);
            pAdapter = pAdapter->Next;
        }
    }
    
    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
    
#else
    // Linux/Android реализация
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        return netInfo;
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            NetworkInterface iface;
            iface.name = ifa->ifa_name;
            
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            iface.ip_address = inet_ntoa(addr_in->sin_addr);
            
            if (ifa->ifa_netmask) {
                struct sockaddr_in* mask_in = (struct sockaddr_in*)ifa->ifa_netmask;
                iface.netmask = inet_ntoa(mask_in->sin_addr);
            }
            
            iface.is_up = (ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING);
            iface.is_wireless = false; // Упрощение
            
            // MAC адрес получить сложнее, пока пропускаем
            iface.mac_address = getMacAddress(iface.name);
            
            netInfo.interfaces.push_back(iface);
        }
    }
    
    freeifaddrs(ifaddr);
#endif
    
    netInfo.external_ip = getExternalIP();
    
    return netInfo;
}

ScreenInfo Utils::getScreenInfo() {
    ScreenInfo screenInfo;
    
#ifdef _WIN32
    screenInfo.width = GetSystemMetrics(SM_CXSCREEN);
    screenInfo.height = GetSystemMetrics(SM_CYSCREEN);
    screenInfo.bits_per_pixel = GetDeviceCaps(GetDC(NULL), BITSPIXEL);
    screenInfo.dpi = GetDeviceCaps(GetDC(NULL), LOGPIXELSX);
    screenInfo.refresh_rate = 60.0; // Упрощение
    screenInfo.orientation = (screenInfo.width > screenInfo.height) ? "landscape" : "portrait";
    
#elif defined(__ANDROID__)
    // На Android это нужно получать через JNI
    screenInfo.width = 1920; // Заглушка
    screenInfo.height = 1080;
    screenInfo.bits_per_pixel = 24;
    screenInfo.dpi = 160;
    screenInfo.refresh_rate = 60.0;
    screenInfo.orientation = "landscape";
    
#else
    // Linux - нужен X11 или Wayland
    screenInfo.width = 1920; // Заглушка
    screenInfo.height = 1080;
    screenInfo.bits_per_pixel = 24;
    screenInfo.dpi = 96;
    screenInfo.refresh_rate = 60.0;
    screenInfo.orientation = "landscape";
#endif
    
    return screenInfo;
}

std::string Utils::getDeviceId() {
#ifdef __ANDROID__
    return getAndroidId();
#elif defined(_WIN32)
    // Используем MAC адрес как device ID
    std::string mac = getMacAddress();
    if (!mac.empty()) {
        return "WIN_" + mac;
    }
    return "WIN_" + generateRandomString(16);
#else
    // Linux - используем hostname + MAC
    std::string hostname = getHostname();
    std::string mac = getMacAddress();
    return "LINUX_" + hostname + "_" + mac;
#endif
}

std::string Utils::getHostname() {
#ifdef _WIN32
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        return std::string(computerName);
    }
    return "unknown";
#else
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
#endif
}

std::string Utils::getCurrentUser() {
#ifdef _WIN32
    char userName[256];
    DWORD size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        return std::string(userName);
    }
    return "unknown";
#else
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "unknown";
#endif
}

// ===== ВРЕМЯ И ДАТА =====

uint64_t Utils::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

uint64_t Utils::getMSTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string Utils::getCurrentTimeString(const std::string& format) {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&time);
    
    std::stringstream ss;
    ss << std::put_time(tm, format.c_str());
    return ss.str();
}

void Utils::sleep(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

// ===== ФАЙЛОВАЯ СИСТЕМА =====

bool Utils::fileExists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

bool Utils::directoryExists(const std::string& path) {
    return std::filesystem::exists(path) && std::filesystem::is_directory(path);
}

bool Utils::createDirectory(const std::string& path, bool recursive) {
    if (recursive) {
        return std::filesystem::create_directories(path);
    } else {
        return std::filesystem::create_directory(path);
    }
}

std::vector<std::string> Utils::listDirectory(const std::string& path) {
    std::vector<std::string> files;
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            files.push_back(entry.path().filename().string());
        }
    } catch (const std::exception& e) {
        logError("Failed to list directory: " + std::string(e.what()));
    }
    
    return files;
}

uint64_t Utils::getFileSize(const std::string& path) {
    try {
        return std::filesystem::file_size(path);
    } catch (const std::exception&) {
        return 0;
    }
}

std::string Utils::getFileExtension(const std::string& path) {
    std::filesystem::path p(path);
    return p.extension().string();
}

std::string Utils::getFileName(const std::string& path) {
    std::filesystem::path p(path);
    return p.filename().string();
}

std::string Utils::getDirectoryName(const std::string& path) {
    std::filesystem::path p(path);
    return p.parent_path().string();
}

std::string Utils::joinPath(const std::string& path1, const std::string& path2) {
    std::filesystem::path p1(path1);
    std::filesystem::path p2(path2);
    return (p1 / p2).string();
}

// ===== СТРОКОВЫЕ УТИЛИТЫ =====

std::string Utils::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

std::string Utils::toLowerCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string Utils::toUpperCase(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

std::vector<std::string> Utils::split(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = str.find(delimiter);
    
    while (end != std::string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }
    
    tokens.push_back(str.substr(start));
    return tokens;
}

std::string Utils::join(const std::vector<std::string>& strings, const std::string& delimiter) {
    if (strings.empty()) return "";
    
    std::stringstream ss;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i > 0) ss << delimiter;
        ss << strings[i];
    }
    return ss.str();
}

bool Utils::startsWith(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

bool Utils::endsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

|";
    for (char c : dangerous) {
        result.erase(std::remove(result.begin(), result.end(), c), result.end());
    }
    
    return trim(result);
}

bool Utils::isPathTraversalAttempt(const std::string& path) {
    return path.find("..") != std::string::npos || 
           path.find("./") != std::string::npos ||
           path.find("\\..") != std::string::npos;
}

// ===== ПРИВАТНЫЕ МЕТОДЫ =====

void Utils::writeLog(LogLevel level, const std::string& message, const std::string& category) {
    std::string timestamp = getCurrentTimeString();
    std::string levelStr = logLevelToString(level);
    std::string categoryStr = category.empty() ? "" : "[" + category + "] ";
    
    std::string logMessage = "[" + timestamp + "] [" + levelStr + "] " + categoryStr + message;
    
    // Вывод в консоль
    std::cout << logMessage << std::endl;
    
#ifdef __ANDROID__
    // Android логирование
    int androidLevel;
    switch (level) {
        case LogLevel::DEBUG: androidLevel = ANDROID_LOG_DEBUG; break;
        case LogLevel::INFO: androidLevel = ANDROID_LOG_INFO; break;
        case LogLevel::WARNING: androidLevel = ANDROID_LOG_WARN; break;
        case LogLevel::ERROR: androidLevel = ANDROID_LOG_ERROR; break;
        case LogLevel::CRITICAL: androidLevel = ANDROID_LOG_FATAL; break;
        default: androidLevel = ANDROID_LOG_INFO; break;
    }
    __android_log_print(androidLevel, "RemoteAccess", "%s", message.c_str());
#endif
    
    // Запись в файл
    if (!log_file_path.empty()) {
        std::ofstream logFile(log_file_path, std::ios::app);
        if (logFile.is_open()) {
            logFile << logMessage << std::endl;
            logFile.close();
        }
    }
}

std::string Utils::logLevelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}