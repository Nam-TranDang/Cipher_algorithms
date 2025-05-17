# 22H1120016 
# Trần Đăng Nam
# Default cho Bigram như slide là một Matrix 6x5 

# Best case: length(plaintext) % 2 = 0 --> tức là plaintext có số lượng ký tự chẵn
# Best case: cho các key có size như matrix  && các giá trị trong key khác nhau 
# Bỏ các ký tự trung trong key - Ví dụ: Key = TRANDANGNAM --> bỏ các giá trị lặp và còn giữ T, R, A, N, D
# Tập ký tự bỏ vào matrix
# Tạo bảng play-fair dựa vào key đã cho 


def single_table_bigram(plaintext, key):
    
    # Bước tạo bảng mã với key
    grid = create_playfair_table(key)
    print_table(grid, f"Bảng đơn '{key}'")
    
    text = plaintext.upper().replace(" ", "")
    result = ""
    i = 0
    
    print("Các bước xử lý Bigram:")
    
    while i < len(text):
        #  Lấy 2 ký tự trong mảng text
        if i + 1 < len(text):
            a, b = text[i], text[i+1]
        else:
            a, b = text[i], 'X'
        
        # tìm Vị trí của 2 ký tự trong grid
        pos_a = find_position(grid, a)
        pos_b = find_position(grid, b)
        
        if not pos_a or not pos_b:
            if not pos_a:
                result += a
            if not pos_b:
                result += b
            i += 2
            print(f"  {a}{b} -> characters not in grid, skipping")
            continue
            
        row_a, col_a = pos_a
        row_b, col_b = pos_b   
        # Rule 1: cùng cột, t sẽ dịch xuống 1 hàng 
        if col_a == col_b:
            row_a_new = (row_a + 1) % len(grid)
            row_b_new = (row_b + 1) % len(grid)
     
        # Luật 2: cùng cột  
        elif row_a == row_b:
            col_a_new = (col_a + 1) % len(grid[0])
            col_b_new = (col_b + 1) % len(grid[0])
        
            new_a = grid[row_a][col_a_new]
            new_b = grid[row_b][col_b_new]
            result += new_a + new_b
            print(f"  {a}{b} -> {new_a}{new_b} (same row rule)")
            
        # Luật 3: Khác cột khác hàng, dùng để tạo hình chữ nhật
        else:
            # Swap cột
            new_a = grid[row_a][col_b]
            new_b = grid[row_b][col_a]
            result += new_a + new_b
            print(f"  {a}{b} -> {new_a}{new_b} (rectangle rule)")
            
        i += 2
    print(f"Kết quả ciphertext: {result}")
    return result

# Hàm print ra terminal bảng mã  Playfair 
def print_table(grid, title="Cipher Table"):
    print(f"\n{title}:") 
    print("-" * 25)
    for row in grid:
        print(" | ".join(row)) 
    print("-" * 25)

def find_position(grid, char):
    """Tìm vị trí của ký tự trong bảng mã Playfair"""
    for i, row in enumerate(grid):
        if char in row:
            return i, row.index(char)
    return None

def create_playfair_table(key):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.,- "  
    
    # Bỏ các giá trị lặp 
    key = "".join(dict.fromkeys(key.upper()))
    
    # Tạo một table - sẽ lưu key trước (key bỏ các giá trị lặp) --> sau đó mới   thêm các ký tự còn lại 
    table = []
    used_chars = set() # Đây là mảng để lưu các ký tự đã được sử dụng - tránh       trùng lặp 
    
    # Vòng for đầu - add key vào mảng trước
    for char in key:
        if (char not in used_chars) and (char in alphabet):
            table.append(char)
            used_chars.add(char) 
    
    # Vòng for thứ 2 - add các ký tự còn lại vào mảng
    for char in alphabet:
        if char not in used_chars:
            table.append(char)
            used_chars.add(char)
    
    # Một default matrix là dạng 6x5 --> thực tế nó là mảng 1 chiều, 
    # và mỗi phần tử của mảng sẽ 1 object lưu 6 ký tự. 
    grid = []
    for i in range(0, len(table), 6):  # Cho giới hạn default là một ma trận 6x5  
        row = table[i:i+6]             # Mỗi row sẽ là 1 mảng 6 phần tử
        grid.append(row)                
    return grid

# Hàm print ra terminal bảng mã Playfair 
def print_table(grid, title="Cipher Table"):
    print(f"\n{title}:") 
    print("-" * 25)
    for row in grid:
        print(" | ".join(row)) 
    print("-" * 25)

def find_position(grid, char):
    """Find the row and column of a character in the grid."""
    for i, row in enumerate(grid):
        if char in row:
            return i, row.index(char)
    return None


def dual_table_bigram(plaintext, key1, key2):

    # Lấy 2 bảng mã để dùng mã hóa 2 bảng bigram 
    grid1 = create_playfair_table(key1)
    grid2 = create_playfair_table(key2)
    
    # In ra 2 bảng mã debug 
    print_table(grid1, f"Dual-table #1 '{key1}'")
    print_table(grid2, f"Dual-table #2 '{key2}'")
    
    # Chuyển đổi plaintext thành chữ hoa và loại bỏ khoảng trắng (dùng replace)
    text = plaintext.upper()
    
    # Xử lý Bigram 
    result = ""
    i = 0 # là index của text - đi từ 0 
    
    print("Các bước xử lý Bigram 2 bảng kép:")
    
    while i < len(text):
        # Lấy 2 giá trị Bigram trong plaintext 
        if i + 1 < len(text): 
            a, b = text[i], text[i+1]
        else:
            # Nếu text length là số lẻ -> add thêm 1 padding value là X 
            a, b = text[i], 'X'
                
        pos_a = find_position(grid1, a)  # ký tự 1 từ  table 1
        pos_b = find_position(grid2, b)  # ký tự 2 từ table 2
        
        if not pos_a or not pos_b:
            # Skip nếu ký tự không có trong bảng mã
            if not pos_a:
                result += a
            if not pos_b:
                result += b
            i += 2
            print(f"  {a}{b} -> ký tự không có trong bảng, skipping")
            continue
            
        row_a, col_a = pos_a
        row_b, col_b = pos_b
        
        print(f"  {a}{b} -> {a} in {pos_a} and {b} in {pos_b}")
        
        # Rule 1: cùng hàng, t sẽ dịch phải 1 cột  
        if row_a == row_b:
            col_a_new = (col_a + 1) % len(grid1[0])
            col_b_new = (col_b + 1) % len(grid2[0])
            
            new_a = grid1[row_a][col_a_new]
            new_b = grid2[row_b][col_b_new]
            result += new_a + new_b
            print(f"  {a}{b} -> {new_a}{new_b} (Rule cùng hàng - shift right cột cùng tables)")

        # Rule 2: Khác cột khác hàng, dùng để tạo hình chữ nhật của 2 bảng 
        else:
            # Cho ký tự đầu từ bảng 1 (row_a, col_a), map với ký tự ở vị trí (row_a, col_b) trong bảng 2
            # Cho ký tự thứ hai từ bảng 2 (row_b, col_b), map với ký tự ở vị trí (row_b, col_a) trong bảng 1
            
            # Kiểm tra nếu vị trí col_b có hợp lệ trong hàng row_a của grid2
            if col_b < len(grid2[row_a]):
                new_a = grid2[row_a][col_b]
            else:
                # Nếu không hợp lệ, giữ nguyên ký tự
                new_a = a
                print(f"  Cảnh bảo: vị trí ({row_a}, {col_b}) vượt ra phạm vi grid2")
            
            # Kiểm tra nếu vị trí col_a có hợp lệ trong hàng row_b của grid1
            if col_a < len(grid1[row_b]):
                new_b = grid1[row_b][col_a]
            else:
                # Nếu không hợp lệ, giữ nguyên ký tự
                new_b = b
                print(f"  Cảnh bảo: vị trí ({row_b}, {col_a}) vượt ra phạm vi grid1")
            
            result += new_a + new_b
            print(f"  {a}{b} -> {new_a}{new_b} (cross-mapping rule)")
            
        i += 2
    
    print(f"Kết quả ciphertext: {result}")
    return result

print("=================================================")
print("22H1120016 --- TRẦN ĐĂNG NAM")
print("THUẬT TOÁN MÃ HÓA BIGRAM BẢNG ĐƠN") 
print("=================================================")
key = "BIGRAM"       
plaintext = "HOCHIMINHVIETNAM" 

encrypted = single_table_bigram(plaintext, key)
print(f"Mã hóa Bigram bảng đơn: {plaintext} -> {encrypted}")



print("=================================================")
print("22H1120016 --- TRẦN ĐĂNG NAM")
print("THUẬT TOÁN MÃ HÓA BIGRAM BẢNG KÉP") 
print("=================================================")
key1 = "BIGRAM"
key2 = "WELCOM"

plaintext1 = "NIJHPQ"
text1 = dual_table_bigram(plaintext1, key1, key2)
print(f"\n Mã hóa Bigram dùng 2 bảng: {plaintext1} -> {text1}")

plaintext2 = "VIETNAMV"
text2 = dual_table_bigram(plaintext2, key1, key2)
print(f"\n Mã hóa Bigram dùng 2 bảng: {plaintext2} -> {text2}")