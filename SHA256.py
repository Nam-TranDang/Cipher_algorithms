# Triển khai thuật toán SHA-256 từ đầu

# Hằng số cho SHA-256: 
# Đây là 64 hằng số đầu tiên từ phần thập phân căn bậc 3 của 64 số nguyên tố đầu tiên - default cho trước
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Giá trị băm ban đầu (H0 đến H7): 
# Đây là 8 hằng số đầu tiên từ phần thập phân căn bậc 2 của 8 số nguyên tố đầu tiên - default 
H0 = 0x6a09e667
H1 = 0xbb67ae85
H2 = 0x3c6ef372
H3 = 0xa54ff53a
H4 = 0x510e527f
H5 = 0x9b05688c
H6 = 0x1f83d9ab
H7 = 0x5be0cd19

# Các phép toán bitwise cơ bản
def rotr(x, n, size=32):
    """Phép xoay phải n bit trong kiểu dữ liệu có kích thước size bit"""
    return ((x >> n) | (x << (size - n))) & 0xFFFFFFFF

def shr(x, n):
    """Phép dịch phải n bit"""
    return x >> n

# Các hàm được định nghĩa trong thuật toán SHA-256
def ch(x, y, z):
    """Hàm lựa chọn: nếu x=1 thì lấy y, ngược lại lấy z"""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Hàm đa số: trả về bit chiếm đa số giữa x, y, z"""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    """Hàm sigma_0 cho biến đổi trong vòng lặp chính"""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    """Hàm sigma_1 cho biến đổi trong vòng lặp chính"""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    """Hàm gamma_0 cho mở rộng lịch khối"""
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def gamma1(x):
    """Hàm gamma_1 cho mở rộng lịch khối"""
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def verify_sha256():
    """22H1120016 - Trần Đăng NamKiểm tra triển khai SHA-256 với các trường hợp thử nghiệm chuẩn"""
    # Các trường hợp thử nghiệm từ FIPS 180-4
    test_cases = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("Tran Dang Nam, toi yeu Viet Nam", 
        "b461970eeac1937267ed9d5c7446d8931bfc70e51fef6efbd3c4d7fef3a2fb2c"),
        ("Toi ten la Tran Dang Nam, toi la nguoi Viet Nam. Toi se la mot nguoi cong dan co ich cho to quoc, cho gia dinh, cho ban than, cho xa hoi."
        ,"81f187a4cd914a76120601fedbadd11e60db02428f3e22af9754ebfb41cd0a0d"),
        ("Vinh quang doi doi thuoc ve dan toc Viet Nam van hien va anh hung. Dang Cong San Viet Nam quang vinh muon nam. Nuoc Cong Hoa Xa Hoi Chu Nghia Viet Nam muon nam. Chu tich Ho Chi Minh vi dai song mai trong su nghiep cua chung ta!",
        "28e76c8f62821528f11d20042fc795fac04e777b3d4f36912136f89170560449")
    ]
    
    print("Kiểm tra SHA-256 với các trường hợp thử nghiệm chuẩn:")
    
    all_passed = True
    for i, (message, expected) in enumerate(test_cases):
        result = sha256(message)
        passed = result == expected
        all_passed &= passed
        
        print(f"\nThử nghiệm {i+1}:")
        print(f"Thông điệp: '{message}'")
        print(f"Kỳ vọng: {expected}")
        print(f"Kết quả: {result}")
        print(f"Kết quả: {'THÀNH CÔNG' if passed else 'THẤT BẠI'}")
    
    if all_passed:
        print("\nTất cả các trường hợp thử nghiệm đều thành công!")
    else:
        print("\nMột số trường hợp thử nghiệm thất bại.")
    
    return all_passed

def pad_message(message):
    """
    Thực hiện đệm thông điệp theo chuẩn SHA-256:
    1. Thêm bit 1
    2. Thêm các bit 0 cho đến khi chiều dài đạt (448 mod 512)
    3. Thêm chiều dài thông điệp ban đầu dưới dạng 64 bit
    """
    # Chuyển thông điệp sang dạng bytes nếu là chuỗi
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Chiều dài ban đầu của thông điệp tính bằng bit
    original_bit_len = len(message) * 8
    
    # Thêm bit 1 (byte 0x80)
    message += b'\x80'
    
    # Thêm các bit 0 cho đến khi chiều dài thông điệp đạt (448 mod 512)
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    
    # Thêm chiều dài ban đầu dưới dạng 64 bit big-endian
    message += original_bit_len.to_bytes(8, byteorder='big')
    
    return message

def sha256(message):
    """Tính giá trị băm SHA-256 cho thông điệp đầu vào"""
    # Đệm thông điệp
    padded_message = pad_message(message)
    
    # Chia thành các khối 512 bit (64 byte)
    blocks = [padded_message[i:i+64] for i in range(0, len(padded_message), 64)]
    
    # Khởi tạo các giá trị băm
    h0, h1, h2, h3, h4, h5, h6, h7 = H0, H1, H2, H3, H4, H5, H6, H7
    
    # Xử lý từng khối 512 bit
    for block in blocks:
        # Chuẩn bị lịch khối: tạo mảng W gồm 64 từ 32-bit
        w = []
        
        # Đầu tiên, chia khối thành 16 từ 32-bit (big-endian)
        for i in range(0, 64, 4):
            w.append(int.from_bytes(block[i:i+4], byteorder='big'))
        
        # Mở rộng 16 từ đầu tiên thành 64 từ
        for i in range(16, 64):
            w.append((gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF)
        
        # Khởi tạo 8 biến làm việc với giá trị băm hiện tại
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        for i in range(64):         # Vòng lặp nén chính
            # Tính T1 và T2
            t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            
            # Cập nhật các biến làm việc
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
        
        # Cập nhật giá trị băm
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
    
    # Nối 8 giá trị băm để tạo kết quả cuối cùng
    digest = (h0.to_bytes(4, byteorder='big') + 
              h1.to_bytes(4, byteorder='big') + 
              h2.to_bytes(4, byteorder='big') + 
              h3.to_bytes(4, byteorder='big') + 
              h4.to_bytes(4, byteorder='big') + 
              h5.to_bytes(4, byteorder='big') + 
              h6.to_bytes(4, byteorder='big') + 
              h7.to_bytes(4, byteorder='big'))
    
    # Chuyển kết quả sang dạng hex
    return digest.hex()

# Hàm để hiển thị từng bước của quá trình tính toán SHA-256
def debug_sha256(message):
    """Tính giá trị băm SHA-256 và hiển thị các bước trung gian"""
    print(f"Thông điệp đầu vào: {message}")
    
    # Đệm thông điệp
    padded_message = pad_message(message)
    print(f"\nThông điệp sau khi đệm (hex): {padded_message.hex()}")
    print(f"Chiều dài thông điệp sau khi đệm (bit): {len(padded_message) * 8}")
    
    # Chia thành các khối 512 bit (64 byte)
    blocks = [padded_message[i:i+64] for i in range(0, len(padded_message), 64)]
    print(f"\nSố lượng khối 512-bit: {len(blocks)}")
    
    # Khởi tạo các giá trị băm
    h0, h1, h2, h3, h4, h5, h6, h7 = H0, H1, H2, H3, H4, H5, H6, H7
    print(f"\nGiá trị băm ban đầu:")
    print(f"h0 = {h0:08x}, h1 = {h1:08x}, h2 = {h2:08x}, h3 = {h3:08x}")
    print(f"h4 = {h4:08x}, h5 = {h5:08x}, h6 = {h6:08x}, h7 = {h7:08x}")
    
    # Xử lý từng khối 512 bit
    for block_idx, block in enumerate(blocks):
        print(f"\n--- Xử lý Khối {block_idx + 1} ---")
        print(f"Khối {block_idx + 1} (hex): {block.hex()}")
        
        # Chuẩn bị lịch khối: tạo mảng W gồm 64 từ 32-bit
        w = []
        
        # Đầu tiên, chia khối thành 16 từ 32-bit (big-endian)
        for i in range(0, 64, 4):
            w.append(int.from_bytes(block[i:i+4], byteorder='big'))
        
        # Mở rộng 16 từ đầu tiên thành 64 từ
        for i in range(16, 64):
            w.append((gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF)
        
        print("\nLịch khối (16 từ đầu tiên từ khối, phần còn lại được suy ra):")
        for i in range(0, 64, 4):
            print(f"W[{i:2d}-{i+3:2d}]: {w[i]:08x} {w[i+1]:08x} {w[i+2]:08x} {w[i+3]:08x}")
        
        # Khởi tạo 8 biến làm việc với giá trị băm hiện tại
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        
        print("\nBiến làm việc ban đầu cho khối này:")
        print(f"a = {a:08x}, b = {b:08x}, c = {c:08x}, d = {d:08x}")
        print(f"e = {e:08x}, f = {f:08x}, g = {g:08x}, h = {h:08x}")
        
        # Vòng lặp nén chính
        for i in range(64):
            if i % 16 == 0:
                print(f"\n-- Vòng {i//16 + 1} (lặp {i}-{i+15}) --")
            
            # Tính T1 và T2
            t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            
            # Lưu các giá trị cũ để in
            old_a, old_b, old_c, old_d = a, b, c, d
            old_e, old_f, old_g, old_h = e, f, g, h
            
            # Cập nhật các biến làm việc
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
            
            if i % 16 == 0 or i % 16 == 15:  # Chỉ in đầu và cuối mỗi vòng
                print(f"Lặp {i:2d}:")
                print(f"  K[{i}] = {K[i]:08x}, W[{i}] = {w[i]:08x}")
                print(f"  t1 = {t1:08x}, t2 = {t2:08x}")
                print(f"  Trước: a={old_a:08x} b={old_b:08x} c={old_c:08x} d={old_d:08x} e={old_e:08x} f={old_f:08x} g={old_g:08x} h={old_h:08x}")
                print(f"  Sau:   a={a:08x} b={b:08x} c={c:08x} d={d:08x} e={e:08x} f={f:08x} g={g:08x} h={h:08x}")
        
        # Cập nhật giá trị băm
        h0_old, h1_old, h2_old, h3_old = h0, h1, h2, h3
        h4_old, h5_old, h6_old, h7_old = h4, h5, h6, h7
        
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF
        
        print("\nCập nhật giá trị băm cho khối này:")
        print(f"Trước: h0={h0_old:08x} h1={h1_old:08x} h2={h2_old:08x} h3={h3_old:08x}")
        print(f"       h4={h4_old:08x} h5={h5_old:08x} h6={h6_old:08x} h7={h7_old:08x}")
        print(f"Sau:   h0={h0:08x} h1={h1:08x} h2={h2:08x} h3={h3:08x}")
        print(f"       h4={h4:08x} h5={h5:08x} h6={h6:08x} h7={h7:08x}")
    
    # Nối 8 giá trị băm để tạo kết quả cuối cùng
    digest = (h0.to_bytes(4, byteorder='big') + 
              h1.to_bytes(4, byteorder='big') + 
              h2.to_bytes(4, byteorder='big') + 
              h3.to_bytes(4, byteorder='big') + 
              h4.to_bytes(4, byteorder='big') + 
              h5.to_bytes(4, byteorder='big') + 
              h6.to_bytes(4, byteorder='big') + 
              h7.to_bytes(4, byteorder='big'))
    
    # Chuyển kết quả sang dạng hex
    hex_digest = digest.hex()
    print(f"\nGiá trị băm SHA-256 cuối cùng: {hex_digest}")
    
    return hex_digest

# Kiểm tra với một số trường hợp chuẩn


# Hàm chính để sử dụng và kiểm tra thuật toán
def main():
    # Kiểm tra với các trường hợp thử nghiệm chuẩn
    print("=== KIỂM TRA THUẬT TOÁN SHA-256 ===\n")
    verify_sha256()

    print("=================================================")
    print("22H1120016 --- TRẦN ĐĂNG NAM")
    print("THUẬT TOÁN THUẬT TOÁN SHA-256")
    print("=================================================")
    while True:
        message = input("\nNhập thông điệp để mã hóa SHA-256 (để trống để thoát): ")
        if not message:
            break
        
        # Sử dụng chế độ debug để hiển thị từng bước
        debug = input("Hiển thị từng bước? (y/n, mặc định là n): ").lower() == 'y'
        
        if debug:
            result = debug_sha256(message)
        else:
            result = sha256(message)
            print(f"\nGiá trị băm SHA-256: {result}")

# Chạy chương trình nếu được gọi trực tiếp
if __name__ == "__main__":
    main()