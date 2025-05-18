import unittest
from transaction import Transaction, TransactionInput, TransactionOutput
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class TestTransactionLogic(unittest.TestCase):

    def setUp(self):
        # Генерация ключей для тестов
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Создание пустой транзакции
        self.tx = Transaction(self.public_key_pem)

    def test_initial_state_is_empty(self):
        # Проверка, что новая транзакция пуста
        self.assertEqual(self.tx.inputs, [])
        self.assertEqual(self.tx.outputs, [])
        self.assertIsNone(self.tx.signature)

    def test_can_attach_inputs_outputs(self):
        # Проверка добавления входов и выходов
        self.tx.add_input(TransactionInput("prev_tx_id_001", 1))
        self.tx.add_output(TransactionOutput(self.public_key_pem, 42.0))
        self.assertEqual(len(self.tx.inputs), 1)
        self.assertEqual(len(self.tx.outputs), 1)

    def test_valid_signature_passes_verification(self):
        # Подпись должна успешно верифицироваться
        self.tx.add_input(TransactionInput("prev_tx_id_002", 0))
        self.tx.add_output(TransactionOutput(self.public_key_pem, 75.0))
        self.tx.generate_signature(self.private_key)
        self.assertTrue(self.tx.verify_signature())

    def test_signature_fails_after_mutation(self):
        # После изменения данных транзакции подпись должна стать недействительной
        self.tx.add_input(TransactionInput("prev_tx_id_003", 0))
        self.tx.add_output(TransactionOutput(self.public_key_pem, 100.0))
        self.tx.generate_signature(self.private_key)
        self.tx.add_output(TransactionOutput(self.public_key_pem, 200.0))  # Изменение
        self.assertFalse(self.tx.verify_signature())

    def test_transaction_id_is_generated_and_changes(self):
        # Идентификатор транзакции должен изменяться при изменении данных
        self.tx.add_input(TransactionInput("txid_abc", 2))
        self.tx.add_output(TransactionOutput(self.public_key_pem, 33.0))
        self.tx.generate_signature(self.private_key)
        self.tx.generate_id()
        first_id = self.tx.transaction_id

        self.tx.add_output(TransactionOutput(self.public_key_pem, 17.0))
        self.tx.generate_id()
        self.assertNotEqual(first_id, self.tx.transaction_id)

    def test_verification_fails_without_signature(self):
        # Верификация без подписи должна вернуть False
        self.tx.add_input(TransactionInput("dummy_tx", 0))
        self.tx.add_output(TransactionOutput(self.public_key_pem, 88.0))
        self.assertFalse(self.tx.verify_signature())

    def test_verification_fails_with_wrong_public_key(self):
        # Подпись не должна верифицироваться с неправильным ключом
        self.tx.add_input(TransactionInput("wrong_key_test", 0))
        self.tx.add_output(TransactionOutput(self.public_key_pem, 99.0))
        self.tx.generate_signature(self.private_key)

        # Подменим публичный ключ (другой)
        another_private_key = ec.generate_private_key(ec.SECP256R1())
        wrong_public_pem = another_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.tx.sender_public_key = wrong_public_pem

        self.assertFalse(self.tx.verify_signature())


if __name__ == "__main__":
    unittest.main()
