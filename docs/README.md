# SecOps Buddy - Документация

Основные инструкции вынесены в `docs/`, чтобы корневой README оставался кратким.

## Основные разделы

- [Установка](installation.md)
- [Настройка](configuration.md)
- [Архитектура](architecture.md)
- [Операции: запуск и мониторинг](operations/monitoring.md)
- [Операции: реальный тест T1030](operations/t1030-real-test.md)
- [Операции: логирование](operations/logging.md)
- [Операции: Telegram-бот](operations/bot.md)
- [MITRE T1030](mitre/T1030.md)
- [План улучшений](improvements.md)

## Что важно посмотреть в первую очередь

- для первого запуска: [Установка](installation.md);
- для снижения false positive: [Настройка](configuration.md), разделы про allowlist/suppressions и cooldown;
- для практического прогона детекции: [Операции: реальный тест T1030](operations/t1030-real-test.md);
- для понимания модулей: [Архитектура](architecture.md).
