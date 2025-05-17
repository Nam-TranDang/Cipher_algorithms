import random
import math

# Check số prime - nguyên tố 
def is_prime(n):
    """
    Kiểm tra xem một số có phải là số nguyên tố hay không.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    
    return True

# Hàm kiểm tra xem alpha có phải là căn nguyên thủy modulo p hay không.
def is_primitive_root(alpha, p):

    # Kiểm tra điều kiện cơ bản: alpha^(p-1) mod p phải bằng 1
    if pow(alpha, p-1, p) != 1:
        return False

    # Tìm các thừa số nguyên tố của p-1
    factors = set()
    n = p - 1
    for i in range(2, int(math.sqrt(n)) + 1):
        while n % i == 0:
            factors.add(i)
            n //= i
    if n > 1:
        factors.add(n)

    # Kiểm tra: alpha^((p-1)/q) mod p != 1 với mọi q
    for q in factors:
        if pow(alpha, (p-1) // q, p) == 1:
            return False    
    return True

# Tìm tập căn nguyên thủy 
def find_primitive_roots(p):
    """
    Tìm tất cả các căn nguyên thủy modulo p và chỉ in ra mảng kết quả.
    """
    primitive_roots = []
    for alpha in range(2, p):
        if is_primitive_root(alpha, p):
            primitive_roots.append(alpha)
    
    print(f"Tập các căn nguyên thủy của G*_{p}: {primitive_roots}")
    return primitive_roots

# Modulo mở rộng -> dùng trong tìm nghịch đảo
def extended_gcd(a, b):
    """
    Thuật toán Euclid mở rộng để tìm UCLN(a, b) và các hệ số x, y sao cho ax + by = UCLN(a, b).
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

# Tìm nghịch đảo modulo ở bước tạo chữ ký số - Alice
def mod_inverse(a, m):
    """
    Tìm nghịch đảo modulo của a theo modulo m.
    - Sử dụng thuật toán Euclid mở rộng để tìm x sao cho ax ≡ 1 (mod m).
    """
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Nghịch đảo modulo không tồn tại')
    else:
        return x % m

# Hàm tạo cặp public - private key của Alice
def elgamal_keygen(p, alpha):
    """
    Tạo cặp khóa ElGamal.
    - p: số nguyên tố
    - alpha: căn nguyên thủy modulo p
    - Trả về: khóa bí mật XA, khóa công khai YA
    """
    print("\nTạo cặp khóa ElGamal:")
    
    
    # Thực ra là từ 1 < Xa < p-1 --> nhưng cho giới hạn đến p-2 để tránh trường hợp biên edge
    XA = random.randint(1, p-2)  # Khóa bí mật 

    print(f"  - Chọn ngẫu nhiên khóa bí mật XA: {XA}")
    YA = pow(alpha, XA, p)  # Khóa công khai
    print(f"  - Tính khóa công khai YA = α^XA mod p = {alpha}^{XA} mod {p} = {YA}")
    
    return XA, YA

# Hàm tạo cặp chữ ký ElGamal của Alice
def elgamal_sign(message, p, alpha, XA, YA):
    """
    Tạo chữ ký ElGamal cho thông điệp.
    - message: thông điệp cần ký
    - p: số nguyên tố
    - alpha: căn nguyên thủy
    - XA: khóa bí mật
    - YA: khóa công khai
    """
    print("\nChữ ký số ElGamal - Ban tạo chữ ký:")
    print(f"Tin nhắn m = {message}")
    
    # Bước 1: Chọn K sao cho 1 < K < p-1 và UCLN(K, p-1) = 1
    while True:
        K_input = input(f"\nNhập giá trị K sao cho 1 < K < {p-1} và gcd(K, p-1) = 1: ")
        try:
            K = int(K_input)
            if 1 < K < p-1:
                gcd_value = math.gcd(K, p-1)
                if gcd_value == 1:
                    break
                else:
                    print(f"gcd(K, p-1) = gcd({K}, {p-1}) = {gcd_value} ≠ 1. Vui lòng chọn K khác.")
            else:
                print(f"K phải nằm trong khoảng (1, {p-1}). Vui lòng nhập lại.")
        except ValueError:
            print("Vui lòng nhập một số nguyên hợp lệ.")
    
    print(f"1. Ban chọn K = {K}, ta có gcd({K}, {p-1}) = {math.gcd(K, p-1)}")
    
    # Bước 2: Tính S1 = alpha^K mod p
    S1 = pow(alpha, K, p)
    print(f"2. Tính S1 = α^K mod p = {alpha}^{K} mod {p} = {S1}")
    
    # Bước 3: Tính K^-1 mod (p-1)
    K_inverse = mod_inverse(K, p-1)
    print(f"3. Tính K^-1 mod (p-1) = {K}^-1 mod {p-1} = {K_inverse}")
    
    # Bước 4: Tính S2 = K^-1 * (m - XA*S1) mod (p-1)
    S2 = (K_inverse * (message - XA * S1)) % (p-1)
    print(f"4. Tính S2 = K^-1 * (m - XA*S1) mod (p-1) = {K_inverse} * ({message} - {XA}*{S1}) mod {p-1} = {S2}")
    print(f"5. Chữ ký bao gồm cặp (S1, S2) = ({S1}, {S2})")
    
    return S1, S2

# Hàm xác thực chữ ký ElGamal - Bob sẽ nhận khóa public của Alice và chữ ký (S1, S2) của Alice 
def elgamal_verify(message, S1, S2, p, alpha, YA, verifier_name="Bob"):
    """
    Xác thực chữ ký ElGamal.
    - message: thông điệp
    - S1, S2: cặp chữ ký
    - p: số nguyên tố
    - alpha: căn nguyên thủy
    - YA: khóa công khai
    - verifier_name: tên người xác thực
    """
    print(f"\n{verifier_name} xác thực chữ ký:")
    
    # Bước 1: Tính V1 = alpha^m mod p
    V1 = pow(alpha, message, p)
    print(f"1. Tính V1 = α^m mod p = {alpha}^{message} mod {p} = {V1}")
    
    # Bước 2: Tính V2 = (YA)^S1 * (S1)^S2 mod p
    V2 = (pow(YA, S1, p) * pow(S1, S2, p)) % p
    print(f"2. Tính V2 = (YA)^S1 * (S1)^S2 mod p = ({YA})^{S1} * ({S1})^{S2} mod {p} = {V2}")
    
    # Bước 3: Kiểm tra V1 = V2
    if V1 == V2:
        print(f"\nChữ ký hợp lệ bởi vì V1 = V2 = {V1}")
        return True
    else:
        print(f"\nChữ ký không hợp lệ bởi vì V1 = {V1} ≠ V2 = {V2}")
        return False

def main():
    print("=================================================")
    print("22H1120016 --- TRẦN ĐĂNG NAM")
    print("THUẬT TOÁN LƯỢC ĐỒ CHỮ KÝ SỐ ELGAMAL")
    print("=================================================")
    print("\nChọn chế độ:")
    print("1. Alice tạo chữ ký và Bob xác thực")
    print("2. Bob xác thực chữ ký")
    
    while True:
        mode_input = input("\nNhập lựa chọn (1 hoặc 2): ")
        if mode_input in ["1", "2"]:
            mode = int(mode_input)
            break
        else:
            print("Lựa chọn không hợp lệ. Vui lòng nhập 1 hoặc 2.")
    
    if mode == 1:
        # Chế độ 1: Alice tạo chữ ký và Bob xác thực

        # Nhập số nguyên tố p
        while True:
            # Nhập số nguyên tố -> tìm căn nguyên thủy (prime number dùng trong mã hóa)
            p_input = input("\nNhập số nguyên tố p (ví dụ: 17, 19, 23, 29, 31,...): ")
            try:
                p = int(p_input)
                if is_prime(p):
                    break
                else:
                    print("Số nhập vào không phải là số nguyên tố. Vui lòng nhập lại.")
            except ValueError:
                print("Vui lòng nhập một số nguyên hợp lệ.")
        
        # Tìm và hiển thị các căn nguyên thủy
        print(f"\nĐang tìm các căn nguyên thủy của G*_{p}... (có thể mất một chút thời gian nếu p lớn)")
        primitive_roots = find_primitive_roots(p)
        
        # Chọn alpha
        while True:
            alpha_input = input(f"\nChọn giá trị alpha từ danh sách căn nguyên thủy (ví dụ: {primitive_roots[0] if primitive_roots else 'không có'}): ")
            try:
                alpha = int(alpha_input)
                if alpha in primitive_roots:
                    break
                else:
                    print(f"Giá trị alpha = {alpha} không phải là căn nguyên thủy của {p}. Vui lòng chọn lại.")
            except ValueError:
                print("Vui lòng nhập một số nguyên hợp lệ.")
        
        # Nhập khóa bí mật của Alice (XA)
        while True:
            XA_input = input(f"\nNhập khóa bí mật của Alice (XA) (1 < XA < {p-1}): ")
            try:
                XA = int(XA_input)
                if 1 < XA < p-1:
                    break
                else:
                    print(f"Khóa bí mật phải nằm trong khoảng (1, {p-1}). Vui lòng nhập lại.")
            except ValueError:
                print("Vui lòng nhập một số nguyên hợp lệ.")
        
        # Tính khóa công khai YA
        YA = pow(alpha, XA, p)
        print(f"\nKhóa công khai của Alice: YA = α^XA mod p = {alpha}^{XA} mod {p} = {YA}")
        print(f"Tập khóa công khai: {{p, α, YA}} = {{{p}, {alpha}, {YA}}}")
        print(f"Khóa bí mật của Ban: XA = {XA}")
        
        # Nhập thông điệp cần ký
        while True:
            message_input = input(f"\nNhập tin nhắn m cần ký (0 ≤ m ≤ {p-1}): ")
            try:
                message = int(message_input)
                if 0 <= message <= p-1:
                    break
                else:
                    print(f"Tin nhắn phải nằm trong khoảng [0, {p-1}]. Vui lòng nhập lại.")
            except ValueError:
                print("Vui lòng nhập một số nguyên hợp lệ.")
        
        # Tạo chữ ký
        S1, S2 = elgamal_sign(message, p, alpha, XA, YA)
        
        # Bob xác thực chữ ký
        elgamal_verify(message, S1, S2, p, alpha, YA)
    
    else:  # mode == 2
        # Chế độ 2: Người khác xác thực chữ ký
        # Nhập tên người xác thực
        verifier_name = input("\nNhập tên của người xác thực: ")
        
        # Nhập các tham số công khai
        while True:
            p_input = input("\nNhập số nguyên tố p (giá trị công khai): ")
            try:
                p = int(p_input)
                if is_prime(p):
                    break
                else:
                    print("Số nhập vào không phải là số nguyên tố. Vui lòng nhập lại.")
            except ValueError:
                print("Vui lòng nhập một số nguyên hợp lệ.")
        
        alpha_input = input("\nNhập giá trị của căn nguyên thủy alpha (giá trị công khai): ")
        alpha = int(alpha_input)
        
        YA_input = input("\nNhập khóa công khai của Ban (YA): ")
        YA = int(YA_input)
        
        message_input = input("\nNhập tin nhắn m cần xác thực: ")
        message = int(message_input)
        
        S1_input = input("\nNhập thành phần S1 của chữ ký: ")
        S1 = int(S1_input)
        
        S2_input = input("\nNhập thành phần S2 của chữ ký: ")
        S2 = int(S2_input)
        
        # Xác thực chữ ký
        elgamal_verify(message, S1, S2, p, alpha, YA, verifier_name)

if __name__ == "__main__":
    main()