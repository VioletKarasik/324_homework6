import hashlib
from typing import List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.hazmat.primitives import serialization


# Вход транзакции ссылается на предыдущую транзакцию
class TransactionInput:
    def __init__(self, previous_tx_id: str, output_index: int):
        self.previous_tx_id = previous_tx_id  # ID предыдущей транзакции
        self.output_index = output_index      # Индекс выхода в предыдущей транзакции

    def __str__(self):
        return f"{self.previous_tx_id}:{self.output_index}"


# Выход транзакции содержит публичный ключ получателя и сумму
class TransactionOutput:
    def __init__(self, recipient_public_key: bytes, amount: float):
        self.recipient_public_key = recipient_public_key  # Публичный ключ получателя
        self.amount = amount                              # Сумма перевода

    def __str__(self):
        # Для идентификации используется хэш публичного ключа
        return f"{hashlib.sha256(self.recipient_public_key).hexdigest()}:{self.amount}"


# Основной класс транзакции
class Transaction:
    def __init__(self, sender_public_key: bytes):
        self.inputs: List[TransactionInput] = []       
        self.outputs: List[TransactionOutput] = []     
        self.sender_public_key = sender_public_key   
        self.signature = None                          
        self.transaction_id = None              

    def add_input(self, tx_input: TransactionInput):
        self.inputs.append(tx_input)                   # Добавить вход

    def add_output(self, tx_output: TransactionOutput):
        self.outputs.append(tx_output)                 # Добавить выход

    # Получение данных для подписи (входы и выходы)
    def _data_to_sign(self) -> bytes:
        data = "".join(str(i) for i in self.inputs)
        data += "".join(str(o) for o in self.outputs)
        return data.encode()

    # Генерация цифровой подписи с использованием приватного ключа
    def generate_signature(self, private_key: ec.EllipticCurvePrivateKey):
        signature = private_key.sign(
            self._data_to_sign(),
            ec.ECDSA(hashes.SHA256())
        )
        self.signature = signature

    # Проверка подписи с использованием публичного ключа
    def verify_signature(self) -> bool:
        if self.signature is None:
            return False
        try:
            public_key = serialization.load_pem_public_key(self.sender_public_key)
            public_key.verify(
                self.signature,
                self._data_to_sign(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    # Генерация уникального ID транзакции на основе данных и подписи
    def generate_id(self):
        base_data = self._data_to_sign()
        if self.signature:
            base_data += self.signature
        self.transaction_id = hashlib.sha256(base_data).hexdigest()
