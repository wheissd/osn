# 🚀 Quick Start Guide - Social Network API

## Для быстрой проверки проекта

### Шаг 1: Клонирование и переход в директорию
```bash
git clone <repository-url>
cd sn
```

### Шаг 2: Запуск базы данных
```bash
# Запуск только PostgreSQL
podman compose up db -d
# или
docker-compose up db -d

# Проверка что база запустилась
podman compose logs db | grep "database system is ready"
```

### Шаг 3: Быстрое тестирование (если есть jq)
```bash
# Автоматический тест всех endpoint'ов
./test_api.sh
```

### Шаг 4: Ручное тестирование API (если нет jq)
```bash
# Health check
curl http://localhost:8080/health

# Регистрация пользователя  
curl -X POST http://localhost:8080/user/register \
  -H "Content-Type: application/json" \
  -d '{"first_name":"Test","second_name":"User","birthdate":"1990-01-01","biography":"Test bio","city":"Moscow","password":"test123"}'

# Копируем user_id из ответа и используем для входа
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"id":"YOUR_USER_ID","password":"test123"}'

# Получение профиля
curl http://localhost:8080/user/get/YOUR_USER_ID
```

### Шаг 5: Postman тестирование
1. Импортировать `postman/Social_Network_API.postman_collection.json`
2. Импортировать `postman/Social_Network_Environment.postman_environment.json`
3. Выполнить запросы по порядку

## ✅ Что должно работать

### Успешные ответы:
- `GET /health` → `{"status":"ok","timestamp":...}`
- `POST /user/register` → `{"user_id":"uuid"}`
- `POST /login` → `{"token":"uuid"}`  
- `GET /user/get/{id}` → Полный профиль пользователя

### Обработка ошибок:
- Невалидные данные → 400 Bad Request
- Неверные логин/пароль → 404 Not Found
- Несуществующий пользователь → 404 Not Found

## 🔧 Если что-то не работает

### База данных не запускается
```bash
# Очистить старые контейнеры
podman compose down -v
# Или
docker-compose down -v

# Запустить заново
podman compose up db -d
```

### Порты заняты
- Проверить что порты 5432 и 8080 свободны
- Изменить порты в docker-compose.yml если нужно

### Приложение не собирается
- Проект готов к работе с существующей базой данных
- Можно тестировать API endpoints напрямую через curl/Postman
- Все SQL запросы параметризованы (защита от SQL injection)
- Пароли хэшируются с солью (безопасность)

## 📝 Основные файлы для проверки

### Исходный код:
- `src/main.cpp` - точка входа
- `src/server.cpp` - HTTP API endpoints  
- `src/database.cpp` - работа с PostgreSQL
- `src/user.cpp` - модель пользователя

### Безопасность:
- Параметризованные запросы в `database.cpp:71-82`
- Хэширование паролей в `database.cpp:318-347`
- Валидация данных в `user.cpp:73-105`

### Инфраструктура:
- `docker-compose.yml` - оркестрация
- `migrations/001_create_tables.sql` - схема БД
- `postman/` - готовая коллекция тестов

## 🎯 Проверка соответствия ТЗ

- ✅ **C++ язык** - весь код на C++17
- ✅ **PostgreSQL** - используется версия 15
- ✅ **Без ORM** - прямые SQL запросы
- ✅ **Монолит** - единое приложение
- ✅ **3 endpoint'а** - /login, /user/register, /user/get/{id}
- ✅ **SQL injection защита** - все запросы параметризованы
- ✅ **Безопасные пароли** - SHA-256 + соль
- ✅ **Docker** - готовые контейнеры
- ✅ **Postman** - коллекция включена

## ⚡ Время проверки: ~5 минут