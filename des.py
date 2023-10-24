from utilities import IP, IP_INV, P, EXPANSION, S_BOXES, PC1, PC2, round_shifts
from bitarray import bitarray
import binascii


class des:
    def __init__(self, key) -> None:
        key_bytes = binascii.a2b_hex(key)
        if (len(key_bytes) != 8):
            raise ValueError(
                'Hexadecimal Represation of of key must be 8 bytes')
        key_bits = bitarray()
        key_bits.frombytes(key_bytes)
        self.key_bits = key_bits

    def _initial_permutation(self, text):
        return bitarray([text[i-1] for i in IP])

    def _final_permutation(self, text):
        return bitarray([text[i-1] for i in IP_INV])

    def _expansion(self, right_half):
        return bitarray([right_half[i-1] for i in EXPANSION])

    def _substitution(self, box, input_bits):
        row = int(input_bits[0] * 2 + input_bits[5])
        col = int(input_bits[1] * 8 + input_bits[2] *
                  4 + input_bits[3] * 2 + input_bits[4])
        value = S_BOXES[box][row][col]
        return format(value, '04b')

    def _permutation(self, right_half):
        permuted = bitarray([right_half[i-1] for i in P])
        return permuted

    def _generate_subkeys(self):
        subkeys = []
        # Initial permutation of the key (PC-1)
        key_bits = bitarray([self.key_bits[i-1] for i in PC1])
        left = key_bits[:28]
        right = key_bits[28:]
        for round_num in range(1, 17):
            # Circular left shift
            left = left[round_shifts[round_num]:] + \
                left[:round_shifts[round_num]]
            right = right[round_shifts[round_num]:] + \
                right[:round_shifts[round_num]]
        # Key permutation (PC-2)
            subkey = bitarray([(left+right)[i-1] for i in PC2])
            subkeys.append(subkey)
        return subkeys

    def _feistel_network(self, right_half, subkey):
        expanded = self._expansion(right_half)
        expanded ^= subkey  # Use the ^= operator to apply the subkey
        output = bitarray()
        for box in range(8):
            input_bits = expanded[box * 6: (box + 1) * 6]
            output_bits = self._substitution(box, input_bits)
            output.extend(output_bits)
        permuted = self._permutation(output)
        return permuted

    def encrypt(self, plaintext):
        
        plaintext_bits = bitarray()
        plaintext_bits.frombytes(plaintext)

        subkeys = self._generate_subkeys()
        # Initial Permutation
        plaintext_bits = self._initial_permutation(plaintext_bits)
        left_half = plaintext_bits[:32]
        right_half = plaintext_bits[32:]
        for round_num in range(16):
            new_right = left_half ^ self._feistel_network(
                right_half, subkeys[round_num])
            left_half = right_half
            right_half = new_right
        ciphertext_bits = right_half + left_half
        # Final permutation (IP^-1)
        ciphertext_bits = self._final_permutation(ciphertext_bits)
        return ciphertext_bits

    def decrypt(self, ciphertext):
        
        ciphertext_bits = bitarray()
        ciphertext_bits.frombytes(ciphertext)
        subkeys = self._generate_subkeys()
        # Initial Permutation
        ciphertext_bits = self._initial_permutation(ciphertext_bits)
        left_half = ciphertext_bits[:32]
        right_half = ciphertext_bits[32:]
        for round_num in range(16):
            new_right = left_half ^ self._feistel_network(
                right_half, subkeys[16 - round_num - 1])
            left_half = right_half
            right_half = new_right
        plaintext_bits = right_half + left_half
        # Final permutation (IP^-1)
        plaintext_bits = self._final_permutation(plaintext_bits)
        return plaintext_bits
