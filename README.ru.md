[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/alm494/tpmcrypto/blob/main/README.md)
[![en](https://img.shields.io/badge/lang-ru-red.svg)](https://github.com/alm494/tpmcrypto/blob/main/README.ru.md)

# tpmcrypto

Простая библиотека для шифрование и дешифрование строковых данных с использованием TPM 2.0 на языке Go. Использует библиотеку от Google, 
которая плохо документирована. Я просто собрал всё воедино, и заставил это работать.

Этот подход использует аппаратные функции модуля TPM 2.0 для обеспечения высокой безопасности при хранении конфиденциальных данных в базах данных.

## Основные особенности 

+ Аппаратная безопасность : используется модуль безопасности TPM 2.0, который доступен на большинстве современных материнских плат, для обеспечения надежной защиты конфиденциальных данных.
+ Криптография, привязанная к машине : зашифрованные данные могут быть расшифрованы только на той же машине, где они были зашифрованы, что гарантирует привязку данных к оборудованию.
+ Управление парой ключей RSA : генерирует и безопасно хранит новую пару ключей RSA размером 2048 бит на чипе TPM с дескриптором,
  который нужно указать в аргументах функций (обратитесь к документации TPM для подробной информации о диапазонах дескрипторов). TPM
  может поддерживать и более сильные алгоритмы шифрования, RSA выбран лишь для максимальной совместимости в качестве примера.
+ Гибридный подход к шифрованию : TPM выполняет асимметричное шифрование/дешифрование с использованием RSA, а симметричное шифрование/дешифрование (AES) обрабатывается программно для повышения эффективности.
+ Кодирование Base64 : объединяет зашифрованный ключ AES и шифротекст, затем кодирует результат в формат Base64 для удобства хранения и передачи.

## Ограничения 

+ Вы должны быть ознакомлены с условиями и ограничениями законодательства вашей страны для оценки правомерности использования
  несертифицированной криптографии.
+ Необходимость привилегированного доступа : для доступа к модулю TPM требуются права root. В качестве альтернативы вы можете добавить своего пользователя в группу tss (это может зависеть от дистрибутива Linux).
+ Зависимость от оборудования : это решение требует наличия модуля TPM 2.0, который может отсутствовать в некоторых системах.
+ Ограничения параллелизма : избегайте многопоточного доступа к TPM, так как это может привести к конкуренции за ресурсы или непредвиденному поведению.

## Пример использования

```Go
// Укажите дескриптор ключа TPM. Нижние значения 0x81000000, 0x81000001 уже
// могуть быть в пользовании вашей системой, и не все они годятся для шифрования
keyHandle := tpmutil.Handle(0x81000100)

// Зашифровать строку
plaintext := "This is a secret password"
encrypted, err := tpmcrypto.EncryptString(plaintext, keyHandle)
if err != nil {
    log.Fatalf("Ошибка шифрования: %v", err)
}
fmt.Printf("Зашифрованная строка:\n%s\n", encrypted)

// Расшифровка
decrypted, err := tpmcrypto.DecryptString(encrypted, keyHandle)
if err != nil {
    log.Fatalf("Ошибка дешифрации: %v", err)
}
fmt.Printf("Расшифрованная строка:\n%s\n", decrypted)
```
         
