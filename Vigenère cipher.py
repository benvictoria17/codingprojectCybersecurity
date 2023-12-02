def decrypt_vigenere(ciphertext, key):
    key_length = len(key)
    decrypted_text = ""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    for i, char in enumerate(ciphertext):
        key_char = key[i % key_length]
        shift = alphabet.find(key_char)
        decrypted_index = (alphabet.find(char) - shift) % 26
        decrypted_char = alphabet[decrypted_index]

        decrypted_text += decrypted_char

        # Printing the step
        print(f"Decrypting '{char}' using key '{key_char}' (shift {shift}). Decrypted letter: '{decrypted_char}'")

    return decrypted_text

ciphertext = "YSSI SEPPM OXFQPAUTPOLAWW".replace(" ", "")
key = "FLOWER"
decrypted_message = decrypt_vigenere(ciphertext, key)
print("\nDecrypted Message:", decrypted_message)
