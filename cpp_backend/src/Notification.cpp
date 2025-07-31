#include "Notification.hpp"
#include <thread>
#include <chrono>

#ifdef __ANDROID__
    #include <android/log.h>
    #include <jni.h>
    #define LOG_TAG "RemoteAccess"
    #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
    #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
    #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#elif defined(_WIN32)
    #include <windows.h>
    #include <shellapi.h>
    #pragma comment(lib, "shell32.lib")
#elif defined(__linux__)
    #include <iostream>
    #include <cstdlib>
#else
    #include <iostream>
#endif

void Notification::show(const std::string& message, NotificationType type) {
    platformShow(message, type);
}

void Notification::showWithActions(
    const std::string& title,
    const std::string& message,
    const std::function<void(NotificationAction)>& callback,
    int timeoutSeconds) {
    
    platformShowWithActions(title, message, callback, timeoutSeconds);
}

void Notification::showRemoteAccessRequest(
    const std::string& requesterName,
    const std::string& requesterIP,
    const std::function<void(bool)>& callback) {
    
    std::string title = "Запрос удалённого доступа";
    std::string message = formatRemoteAccessMessage(requesterName, requesterIP);
    
    showWithActions(title, message, [callback](NotificationAction action) {
        callback(action == NotificationAction::ALLOW);
    }, 30);
}

void Notification::showConnectionEstablished(const std::string& clientName) {
    std::string message = "Подключение установлено с: " + clientName;
    show(message, NotificationType::SUCCESS);
}

void Notification::showConnectionLost(const std::string& reason) {
    std::string message = "Соединение потеряно";
    if (!reason.empty()) {
        message += " (" + reason + ")";
    }
    show(message, NotificationType::WARNING);
}

void Notification::showSecurityWarning(const std::string& warning) {
    show("ПРЕДУПРЕЖДЕНИЕ: " + warning, NotificationType::WARNING);
}

void Notification::showError(const std::string& error) {
    show(error, NotificationType::ERROR);
}

void Notification::showSuccess(const std::string& message) {
    show(message, NotificationType::SUCCESS);
}

void Notification::platformShow(const std::string& message, NotificationType type) {
#ifdef __ANDROID__
    std::string fullMessage = getTypePrefix(type) + message;
    switch (type) {
        case NotificationType::ERROR:
            LOGE("%s", fullMessage.c_str());
            break;
        case NotificationType::WARNING:
            LOGW("%s", fullMessage.c_str());
            break;
        default:
            LOGI("%s", fullMessage.c_str());
            break;
    }
    
    // TODO: Здесь можно добавить вызов Java метода для показа Android Toast/Notification
    
#elif defined(_WIN32)
    UINT iconType = MB_ICONINFORMATION;
    std::string title = "RemoteAccess";
    
    switch (type) {
        case NotificationType::ERROR:
            iconType = MB_ICONERROR;
            title += " - Ошибка";
            break;
        case NotificationType::WARNING:
            iconType = MB_ICONWARNING;
            title += " - Предупреждение";
            break;
        case NotificationType::SUCCESS:
            iconType = MB_ICONINFORMATION;
            title += " - Успешно";
            break;
        case NotificationType::REQUEST:
            iconType = MB_ICONQUESTION;
            title += " - Запрос";
            break;
        default:
            iconType = MB_ICONINFORMATION;
            break;
    }
    
    MessageBoxA(NULL, message.c_str(), title.c_str(), MB_OK | iconType);
    
#elif defined(__linux__)
    std::string fullMessage = getTypePrefix(type) + message;
    
    // Попытка использовать notify-send для системных уведомлений
    std::string command = "notify-send \"RemoteAccess\" \"" + message + "\" 2>/dev/null";
    int result = system(command.c_str());
    
    // Если notify-send недоступен, выводим в консоль
    if (result != 0) {
        std::cout << "[NOTIFY] " << fullMessage << std::endl;
    }
    
#else
    std::string fullMessage = getTypePrefix(type) + message;
    std::cout << "[NOTIFY] " << fullMessage << std::endl;
#endif
}

void Notification::platformShowWithActions(
    const std::string& title,
    const std::string& message,
    const std::function<void(NotificationAction)>& callback,
    int timeoutSeconds) {
    
#ifdef __ANDROID__
    // На Android это должно быть реализовано через JNI вызовы к Java коду
    // который покажет диалог с кнопками "Разрешить" и "Отклонить"
    LOGI("REQUEST: %s - %s", title.c_str(), message.c_str());
    
    // Временная заглушка - автоматический отказ через таймаут
    std::thread([callback, timeoutSeconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(timeoutSeconds));
        callback(NotificationAction::DENY);
    }).detach();
    
#elif defined(_WIN32)
    std::string fullMessage = message + "\n\nНажмите 'Да' чтобы разрешить, 'Нет' чтобы отклонить.";
    
    // Создаём отдельный поток для показа диалога с таймаутом
    std::thread([title, fullMessage, callback, timeoutSeconds]() {
        int result = MessageBoxA(NULL, fullMessage.c_str(), title.c_str(), 
                                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
        
        if (result == IDYES) {
            callback(NotificationAction::ALLOW);
        } else {
            callback(NotificationAction::DENY);
        }
    }).detach();
    
    // Таймаут
    std::thread([callback, timeoutSeconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(timeoutSeconds));
        callback(NotificationAction::DENY);
    }).detach();
    
#elif defined(__linux__)
    // Используем zenity для показа диалога на Linux
    std::string command = "zenity --question --title=\"" + title + 
                         "\" --text=\"" + message + 
                         "\" --ok-label=\"Разрешить\" --cancel-label=\"Отклонить\" --timeout=" + 
                         std::to_string(timeoutSeconds);
    
    std::thread([command, callback]() {
        int result = system(command.c_str());
        if (result == 0) {
            callback(NotificationAction::ALLOW);
        } else {
            callback(NotificationAction::DENY);
        }
    }).detach();
    
#else
    // Консольная версия
    std::cout << "\n=== " << title << " ===\n";
    std::cout << message << "\n";
    std::cout << "Введите 'y' для разрешения, любой другой символ для отказа: ";
    
    std::thread([callback, timeoutSeconds]() {
        std::this_thread::sleep_for(std::chrono::seconds(timeoutSeconds));
        std::cout << "\nВремя ожидания истекло. Запрос отклонён.\n";
        callback(NotificationAction::DENY);
    }).detach();
    
    // В реальном приложении здесь должна быть неблокирующая обработка ввода
    callback(NotificationAction::DENY);
#endif
}

std::string Notification::getTypePrefix(NotificationType type) {
    switch (type) {
        case NotificationType::ERROR:
            return "[ОШИБКА] ";
        case NotificationType::WARNING:
            return "[ПРЕДУПРЕЖДЕНИЕ] ";
        case NotificationType::SUCCESS:
            return "[УСПЕШНО] ";
        case NotificationType::REQUEST:
            return "[ЗАПРОС] ";
        default:
            return "[ИНФО] ";
    }
}

std::string Notification::formatRemoteAccessMessage(const std::string& requesterName, const std::string& requesterIP) {
    std::string message = "Пользователь \"" + requesterName + 
                         "\" (IP: " + requesterIP + 
                         ") запрашивает разрешение на удалённое управление вашим устройством.\n\n";
    message += "⚠️ ВНИМАНИЕ: Предоставление доступа позволит удалённому пользователю:\n";
    message += "• Управлять вашим экраном\n";
    message += "• Использовать клавиатуру и мышь\n";
    message += "• Получить доступ к файлам\n\n";
    message += "Разрешить подключение?";
    
    return message;
}