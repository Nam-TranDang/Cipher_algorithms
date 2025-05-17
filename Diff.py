# Triển khai thuật toán Diffie-Hellman với đầu vào từ người dùng
import random

def is_prime(num):
    """Kiểm tra số nguyên tố"""
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def find_primitive_root(p):
    # Hàm tìm căn nguyên thủy - chỉ dùng prime numb 
    if not is_prime(p):
        raise ValueError("Số p phải là số nguyên tố")
    
    # Tìm phần tử sinh (chỉ các số nguyên tố nhỏ)
    for g in range(2, p):
        # Tạo tập hợp các số g^i mod p với i từ 1 đến p-1
        powers = set()
        for i in range(1, p):
            power = pow(g, i, p)
            powers.add(power)
        
        # Nếu tập hợp có kích thước p-1, tức là tất cả các số từ 1 đến p-1 được tạo ra
        if len(powers) == p - 1:
            return g
    
    return None

def suggest_primitive_root(p):
    """Gợi ý một căn nguyên thủy cho số nguyên tố p - dùng cho số g (optional)"""
    if p <= 100:
        # Cho số nhỏ, tìm căn nguyên thủy thực sự
        g = find_primitive_root(p)
        if g:
            return g
    
    # Cho số lớn, chọn một số ngẫu nhiên (trong thực tế, cần phương pháp kiểm tra tốt hơn)
    candidates = []
    for _ in range(5):
        g = random.randint(2, p-1)
        # Kiểm tra nhanh xem g có khả năng là căn nguyên thủy không
        if pow(g, (p-1)//2, p) != 1:
            candidates.append(g)
    
    return candidates[0] if candidates else 2

def get_valid_input(prompt, validation_fn=None, error_msg=None, default=None):
    
    while True:
        try:
            if default is not None:
                user_input = input(f"{prompt} (mặc định: {default}): ") or str(default)
            else:
                user_input = input(f"{prompt}: ")
            
            # Chuyển đổi kiểu dữ liệu (mặc định là int)
            value = int(user_input)
            
            # Kiểm tra tính hợp lệ nếu có hàm kiểm tra
            if validation_fn and not validation_fn(value):
                if error_msg:
                    print(error_msg)
                continue
                
            return value
        except ValueError:
            print("Lỗi: Vui lòng nhập một số nguyên hợp lệ.")

def diffie_hellman():
    
    # Bước 1: Nhập số nguyên tố p từ người dùng - hàm kiểm tra nhập đúng 
    p = get_valid_input(
        "Nhập số nguyên tố p (khuyến nghị p > 10)",
        validation_fn=lambda x: x > 1,
        error_msg="Số p phải lớn hơn 1"
    )
    
    # Kiểm tra xem p có phải là số nguyên tố không
    if not is_prime(p):
        print(f"Cảnh báo: {p} không phải là số nguyên tố. Điều này có thể ảnh hưởng đến độ an toàn của thuật toán.")
        proceed = input("Bạn có muốn tiếp tục? (y/n): ").lower()
        if proceed != 'y':
            print("Đã hủy thao tác.")
            return
    
    # Gợi ý một căn nguyên thủy g
    suggested_g = suggest_primitive_root(p)
    
   # Tìm tất cả các căn nguyên thủy
    primitive_roots = []
    for g in range(2, p):
        powers = set(pow(g, i, p) for i in range(1, p))
        if len(powers) == p - 1:
            primitive_roots.append(g)
    print(f"Các căn nguyên thủy của {p}: {primitive_roots}")

    # Bước 1: Nhập căn nguyên thủy g từ người dùng
    g = get_valid_input(
        f"Nhập căn nguyên thủy g (2 <= g < p, đề xuất: {suggested_g})",
        validation_fn=lambda x: 1 < x < p,
        error_msg=f"g phải nằm giữa 2 và {p-1}",
        default=suggested_g
    )
    
    print(f"\nThông số công khai: P = {p}, G = {g}")
    
    # Bước 2: Nhập khóa riêng a và b từ người dùng
    print("\n--- Nhập khóa riêng (giữ bí mật) ---")
    a = get_valid_input(
        "Nhập khóa riêng của Alice (a < p)",
        validation_fn=lambda x: 1 <= x < p,
        error_msg=f"Khóa riêng phải nằm giữa 1 và {p-1}"
    )
    
    b = get_valid_input(
        "Nhập khóa riêng của Bob (b < p)",
        validation_fn=lambda x: 1 <= x < p,
        error_msg=f"Khóa riêng phải nằm giữa 1 và {p-1}"
    )
    
    print(f"\nAlice chọn khóa riêng a = {a}")
    print(f"Bob chọn khóa riêng b = {b}")
    
    # Bước 3: Tính giá trị công khai để trao đổi
    # Alice tính x = (g^a mod p)
    x = pow(g, a, p)
    # Bob tính y = (g^b mod p)
    y = pow(g, b, p)
    
    print(f"\nAlice tính giá trị công khai x = ({g}^{a} mod {p}) = {x}")
    print(f"Bob tính giá trị công khai y = ({g}^{b} mod {p}) = {y}")
    
    # Bước 4 & 5: Trao đổi giá trị công khai
    print(f"\nAlice và Bob trao đổi các giá trị công khai với nhau")
    print(f"Alice nhận y = {y} từ Bob")
    print(f"Bob nhận x = {x} từ Alice")
    
    # Bước 6: Tính khóa bí mật chung
    # Alice tính khóa bí mật: ka = (y^a mod p)
    ka = pow(y, a, p)
    # Bob tính khóa bí mật: kb = (x^b mod p)
    kb = pow(x, b, p)
    
    print(f"\nAlice tính khóa bí mật: ka = (y^a mod p) = ({y}^{a} mod {p}) = {ka}")
    print(f"Bob tính khóa bí mật: kb = (x^b mod p) = ({x}^{b} mod {p}) = {kb}")
    
    # Bước 7: Xác nhận cả hai bên có cùng khóa bí mật
    if ka == kb:
        print(f"\nXác nhận: Alice và Bob đã tạo ra cùng một khóa bí mật chung: {ka}")
        return ka
    else:
        print("\nLỗi: Khóa bí mật không khớp! Có vấn đề trong tính toán.")
        return None
 

if __name__ == "__main__":
    print("=================================================")
    print("22H1120016 --- TRẦN ĐĂNG NAM")
    print("THUẬT TOÁN TRAO ĐỔI KHÓA DIFFIE-HELLMAN")
    print("=================================================")
    diffie_hellman()