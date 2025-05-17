# AES 128 - Block Cipher
#VIETNAMUKRAINE12 - key
#SAIGONODESSA2023 - plaintext

#Default bảng S-box & RCON (Hexa - 32 bits = 8 (ký tự hex) * 4 bits)
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
]

# Rotword - dùng trong việc swap cột cuối của key (diễn ra ở từng bước). Từ key 0 đến key 10
def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

# Subword - cột cuối -> dùng tìm key
def sub_word(word):
    return (
        (SBOX[(word >> 24) & 0xFF] << 24) |
        (SBOX[(word >> 16) & 0xFF] << 16) |
        (SBOX[(word >> 8) & 0xFF] << 8) |
        (SBOX[word & 0xFF])
    )

# Chạy XOR 
def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Hàm đi dò sub-bytes 
def sub_bytes(state):
    return [SBOX[b] for b in state]

# Hàm ShiftRows - Xử lý từng round 
def shift_rows(state):
    matrix = [state[i::4] for i in range(4)]
    for i in range(1, 4): matrix[i] = matrix[i][i:] + matrix[i][:i]
    return [matrix[i][j] for j in range(4) for i in range(4)]

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

# Hàm MixColumns - Xử lý từng round 
def mix_single_column(col):
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u)
    return col

def mix_columns(state):
    state_cols = [state[i:i+4] for i in range(0, 16, 4)]
    mixed = []
    for col in state_cols:
        mixed.extend(mix_single_column(col.copy()))
    return mixed

# Sinh khóa 
def key_expansion(key_bytes):
    # Ví dụ Key = VIETNAMUKRAINE12  --> tức có 16 bytes, và đang cần tách ra mỗi w  = 4 bytes 
    # Vì input  data là 128 bit = 16 bytes = 16 ký tự --> ở w sẽ là w[0 đến 3]. Và w[0] = "VIET", và lưu trữ mỗi w = 4 bytes (32 bits)
    w = [int.from_bytes(key_bytes[i:i+4], 'big') for i in range(0, 16, 4)]
    
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[(i // 4) - 1]
        w.append(w[i - 4] ^ temp)
    return w

# Định hình lại matrix 4x4 
def format_matrix(key_bytes):
    matrix = [[0]*4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            matrix[row][col] = key_bytes[col*4 + row]
    return matrix

# 2 hàm in matrix (1 cái để in initial key, 1 cái để in key schedule)
def print_single_matrix(matrix, title):
    print(f"\n{title}")
    for row in matrix:
        print(" ".join(f"{b:02X}" for b in row))
    print("-" * (4 * 3 - 1))

# In một hàng matrix ở dạng ngang
def print_horizontal_matrices(matrices, titles, matrix_width=11):
    num_matrices = len(matrices)
    if num_matrices == 0:
        return
    num_rows = len(matrices[0])

    # In title 
    title_row = ""
    for title in titles:
        title_row += title.center(matrix_width) + "    "  # Add spacing between titles
    print(title_row.rstrip())  # Remove trailing spaces

    # Print separator 
    print("-" * (num_matrices * matrix_width + (num_matrices - 1) * 4)) # Adjust line length for spacing

    for r in range(num_rows):
        row_str = ""
        for i in range(num_matrices):
            row_str += " ".join(f"{byte:02X}" for byte in matrices[i][r]) + "    " 
        print(row_str.rstrip()) 
    print()



# ----------------------- Chương trình ở đây - vì đang xử lý 128 bits - cho input thuộc 0 - 127 ở trong bảng ASCII (thuộc unicode) 
print("=================================================")
print("22H1120016 --- TRẦN ĐĂNG NAM")
print("THUẬT TOÁN AES 128 BIT")
print("=================================================")
key_input_str = input("Nhập khóa AES 16 ký tự liền nhau: ")
if len(key_input_str) != 16:
    print("Khóa phải đúng 16 ký tự!")
    exit()

key_input = key_input_str.encode('utf-8') # Convert hết thành bytes ví dụ khóa đúng 16 key = 128 bits 

# Bước 1: Sinh khóa từ khóa AES
expanded = key_expansion(key_input) 
round_keys = [b''.join(w.to_bytes(4, 'big') for w in expanded[4*i:4*i+4]) for i in range(11)]

# Hiển thị key schedule
print("\nSinh khóa từ khóa AES:")
all_round_matrices = [] # Object array: store các matrix key từ 0 - 10 
round_titles = []
for r in range(11):
    matrix = format_matrix(round_keys[r])  
    all_round_matrices.append(matrix)
    round_titles.append(f"Key {r}")

print_single_matrix(all_round_matrices[0], round_titles[0])
print("Hàng 1:")
print_horizontal_matrices(all_round_matrices[1:6], round_titles[1:6]) # In 5 matrix key 
print("Hàng 2:")
print_horizontal_matrices(all_round_matrices[6:], round_titles[6:]) # In 5 matrix key tiếp theo

# ------------------------------------------------------------------------------------------

# Nhập plaintext
plaintext_str = input("\nNhập thông điệp cần mã hóa (16 ký tự): ")
if len(plaintext_str) != 16:
    print(" Thông điệp phải đúng 16 ký tự!")
    exit()

plaintext = plaintext_str.encode('utf-8')

# Hiển thị ma trận hex plaintext 
print("\nMa trận hex của thông điệp đầu vào:")
print_single_matrix(format_matrix(plaintext), "Plaintext Input")

# Bước 2: Tính toán các Round - Encrypt Plaintext 
# In + XOR Round đầu tiên: chỉ xor với plaintext + key 0
print("\nCác bước sau mỗi vòng:")
state = list(xor_bytes(plaintext, round_keys[0])) 
round_matrices = [format_matrix(bytes(state))]
round_titles = ["State 0"]

# Tính toán từ Round 1 - 10 (Đi qua 4 bước trong mỗi vòng): # SubBytes, ShiftRows, MixColumns, AddRoundKey (vòng thứ 10 không chơi với MixColumns)
for r in range(1, 11):
    state = sub_bytes(state) # Bước 1: SubBytes
    round_matrices.append(format_matrix(bytes(state)))
    round_titles.append(f"Round {r} - SubBytes")

    state = shift_rows(state) # Bước 2: ShiftRows
    round_matrices.append(format_matrix(bytes(state)))
    round_titles.append(f"Round {r} - ShiftRows")

    if r != 10:
        state = mix_columns(state) # Bước "Special": MixColumns (chỉ đi từ roudn 1 - 9)
        round_matrices.append(format_matrix(bytes(state)))
        round_titles.append(f"Round {r} - MixColumns")

    state = list(xor_bytes(state, round_keys[r])) # Bước 3: AddRoundKey (từ key 1- 10)
    round_matrices.append(format_matrix(bytes(state)))
    round_titles.append(f"State {r}")

# In ra các round state, SubBytes, ShiftRows, MixColumns, AddRoundKey (của từng cho 10 round)
matrix_width = 19
for i in range(0, len(round_titles)):
    if round_titles[i].startswith("State"):
        print(f"\n{round_titles[i]}:")
        print_single_matrix(round_matrices[i], title="")
    elif "SubBytes" in round_titles[i]:
        titles = [round_titles[i]]
        matrices = [round_matrices[i]]
        if i + 1 < len(round_titles) and "ShiftRows" in round_titles[i + 1]:
            titles.append(round_titles[i + 1])
            matrices.append(round_matrices[i + 1])
            if i + 2 < len(round_titles) and "MixColumns" in round_titles[i + 2]:
                titles.append(round_titles[i + 2])
                matrices.append(round_matrices[i + 2])
        print_horizontal_matrices(matrices, titles, matrix_width)
    elif "ShiftRows" in round_titles[i] and "SubBytes" not in round_titles[i] and "MixColumns" not in round_titles[i]:
        pass
    elif "MixColumns" in round_titles[i]:
        pass

# In kết quả cuối 
ciphertext = bytes(state)
print("\n Ciphertext (hex):", ciphertext.hex().upper())