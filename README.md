# 324_homework6
# Криптографическая реализация транзакций

Реализация базовой структуры транзакций на Python с использованием цифровой подписи и проверки на основе асимметричного шифрования (ECDSA, SHA-256). Подходит как демонстрационный пример механизма верификации подлинности транзакций в блокчейн-подобных системах.

---

## 📚 Описание структуры

### 🧱 Классы

- `TransactionInput` — вход транзакции, указывает на ID предыдущей транзакции и индекс выхода.
- `TransactionOutput` — выход транзакции, содержит сумму и публичный ключ получателя.
- `Transaction` — основной объект, поддерживает:
  - добавление входов/выходов,
  - генерацию цифровой подписи (ECDSA),
  - проверку подписи,
  - формирование идентификатора транзакции (`transaction_id`).

---

## 🔐 Подпись и проверка

1. **Формирование данных:** Все входы и выходы сериализуются в строку и кодируются в байты.
2. **Подпись:** С помощью закрытого ключа создаётся подпись данных.
3. **Проверка:** Публичный ключ используется для проверки подлинности подписи.
4. **ID транзакции:** Хеш всех данных и подписи формирует уникальный `transaction_id`.

---

## 💡 Пример использования

```python
from transaction import Transaction, TransactionInput, TransactionOutput
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
```

# Генерация пары ключей
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Создание транзакции
tx = Transaction(public_key)
tx.add_input(TransactionInput("prev_tx_001", 0))
tx.add_output(TransactionOutput(public_key, 100.0))

# Подпись и проверка
tx.generate_signature(private_key)
print("Подпись корректна:", tx.verify_signature())

# Генерация ID
tx.generate_id()
print("Transaction ID:", tx.transaction_id)

# Юнит-тесты
В файле test_transaction.py реализированы тесты с использованием unittest. Проверяются:
  - создание и начальное состояние транзакции;
  - добавление входов/выходов;
  - корректность подписи;
  - изменение данных после подписи;
  - генерация и обновление идентификатора.

## Ограничения
- Не является полноценной реализацией блокчейна.
- Нет механизма проверки UTXO или баланса.

## Требования

- Python 3.x
- Библиотека cryptography (pip install cryptography)

## Установка

Для начала работы с проектом просто склонируйте репозиторий или загрузите файлы.

### Командная строка
Запустите тесты:
```bash
python -m unittest test_transaction.py
```

### Структура проекта
transaction.py           # Основная реализация транзакции
test_transaction.py      # Юнит-тесты
README.md                # Документация 