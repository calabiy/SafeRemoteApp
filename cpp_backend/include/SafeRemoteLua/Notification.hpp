#ifndef NOTIFICATION_HPP
#define NOTIFICATION_HPP

#include <string>
#include <functional>

enum class NotificationType {
    INFO,
    WARNING,
    REQUEST,
    SUCCESS,
    ERROR
};

enum class NotificationAction {
    ALLOW,
    DENY,
    DISMISS
};

class Notification {
public:
    // Базовое уведомление
    static void show(const std::string& message, NotificationType type = NotificationType::INFO);
    
    // Уведомление с кнопками действий (для запросов разрешений)
    static void showWithActions(
        const std::string& title,
        const std::string& message,
        const std::function<void(NotificationAction)>& callback,
        int timeoutSeconds = 30
    );
    
    // Специализированные методы для приложения удалённого доступа
    static void showRemoteAccessRequest(
        const std::string& requesterName,
        const std::string& requesterIP,
        const std::function<void(bool)>& callback
    );
    
    static void showConnectionEstablished(const std::string& clientName);
    static void showConnectionLost(const std::string& reason = "");
    static void showSecurityWarning(const std::string& warning);
    
    // Системные уведомления
    static void showError(const std::string& error);
    static void showSuccess(const std::string& message);

private:
    static void platformShow(const std::string& message, NotificationType type);
    static void platformShowWithActions(
        const std::string& title,
        const std::string& message,
        const std::function<void(NotificationAction)>& callback,
        int timeoutSeconds
    );
    
    static std::string getTypePrefix(NotificationType type);
    static std::string formatRemoteAccessMessage(const std::string& requesterName, const std::string& requesterIP);
};

#endif // NOTIFICATION_HPP