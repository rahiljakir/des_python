from des import des
import binascii
import bitarray


key = "AABB09182736CCDD"
Cipher = des(key)

print("Plain-Text Data: ", "123456ABCD132536")
encrypted_bytes = Cipher.encrypt(
    binascii.a2b_hex("123456ABCD132536")).tobytes()
encrypted_hex_rep = binascii.hexlify(encrypted_bytes)
print("Encrypted Data: ", encrypted_hex_rep)


decrypted_bytes = Cipher.decrypt(encrypted_bytes)
decrypted_hex_rep = binascii.hexlify(decrypted_bytes)
print("Decrypted Data: ", decrypted_hex_rep)
