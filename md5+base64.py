import hashlib
import base64
import os

# ---==[ SETTINGS - قم بتعديل هذه المتغيرات ]==---

# 1. The username to use for encoding
# اسم المستخدم الذي سيتم استخدامه في التشفير
USERNAME = "carlos"

# 2. Input file name
# اسم الملف الذي يحتوي على قائمة كلمات المرور
INPUT_FILE = "path\passwords.txt"

# 3. Output file name
# اسم الملف الذي سيتم حفظ النتائج المشفرة فيه
OUTPUT_FILE = "path\encoded_cookies.txt"

# ---==[ End of Settings ]==---


def encode_password(username, password):
    """
    Encodes a single password according to the format: base64(username:md5(password))
    تقوم بتشفير كلمة مرور واحدة حسب الصيغة المطلوبة
    """
    # Step 1: Calculate the MD5 hash of the password
    # الخطوة 1: حساب MD5 hash لكلمة المرور
    md5_hasher = hashlib.md5()
    md5_hasher.update(password.encode('utf-8'))
    md5_password = md5_hasher.hexdigest()
    
    # Step 2: Create the string "username:md5_hash"
    # الخطوة 2: إنشاء النص "username:md5_hash"
    combined_string = f"{username}:{md5_password}"
    
    # Step 3: Base64 encode the entire string
    # الخطوة 3: تشفير النص بالكامل باستخدام Base64
    base64_encoded_string = base64.b64encode(combined_string.encode('utf-8')).decode('utf-8')
    
    return base64_encoded_string


def main():
    """
    Main function to read passwords, encode them, and save to a new file.
    الدالة الرئيسية لقراءة كلمات المرور، تشفيرها، وحفظها في ملف جديد
    """
    print("--- Starting Password Encoding Process ---")

    # Check if the input file exists
    # التحقق من وجود ملف الإدخال
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Error: Input file '{INPUT_FILE}' not found.")
        print("[!] Please create this file and add passwords to it, one per line.")
        return

    # Read all passwords from the input file
    # قراءة جميع كلمات المرور من ملف الإدخال
    with open(INPUT_FILE, "r") as f_in:
        passwords = [line.strip() for line in f_in.readlines() if line.strip()]
    
    if not passwords:
        print(f"[!] Warning: Input file '{INPUT_FILE}' is empty.")
        return

    print(f"[+] Found {len(passwords)} passwords in '{INPUT_FILE}'.")

    encoded_results = []
    # Loop through each password and encode it
    # المرور على كل كلمة مرور وتشفيرها
    for password in passwords:
        encoded_value = encode_password(USERNAME, password)
        encoded_results.append(encoded_value)
        print(f"  - Original: '{password}'  =>  Encoded: '{encoded_value}'")

    # Save the encoded results to the output file
    # حفظ النتائج المشفرة في ملف الإخراج
    with open(OUTPUT_FILE, "w") as f_out:
        for result in encoded_results:
            f_out.write(result + "\n")

    print(f"\n[+] Success! All encoded values have been saved to '{OUTPUT_FILE}'.")


if __name__ == "__main__":
    main()

