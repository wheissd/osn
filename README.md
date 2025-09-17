# Social Network API

Простое REST API для социальной сети на C++ с поддержкой кириллицы.

## Быстрый старт

### Требования
- Docker и Docker Compose
- jq (для тестов)

### Запуск
```bash
# Клонировать репозиторий
git clone <repo-url>
cd sn

# Запустить все сервисы
docker-compose up -d --build

# Проверить работоспособность
curl http://localhost:8080/health
```

### Тестирование
```bash
# Запустить автоматические тесты
./test_api.sh
```

## API Endpoints

### Регистрация пользователя
```bash
POST /user/register
Content-Type: application/json

{
  "first_name": "Иван",
  "second_name": "Иванов",
  "birthdate": "1990-01-01",
  "biography": "О себе",
  "city": "Москва",
  "password": "password123"
}
```

### Вход в систему
```bash
POST /login
Content-Type: application/json

{
  "id": "user-uuid",
  "password": "password123"
}
```

### Получение профиля
```bash
GET /user/get/{user_id}
```

## Остановка
```bash
docker-compose down
```

## Структура проекта
```
src/          # Исходный код C++
include/      # Заголовочные файлы
migrations/   # SQL миграции
test_api.sh   # Тесты API
```

Поддерживает кириллические имена и UTF-8 кодировку.