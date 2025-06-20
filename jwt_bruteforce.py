import base64
import hashlib
import hmac
import json
import sys
import threading
import time

# Global state
running = True
candidate = ""
start_time = 0

# Charset: common characters used in industry
CHARSET = list(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*()-_+=[]{};:'\",.<>?/\\|`~"
)


def extract_alg_from_header(header_json_str):
    try:
        header = json.loads(header_json_str)
        return header.get("alg")
    except json.JSONDecodeError:
        return None


def hmac_base64url(data, key, alg):
    if alg == 'HS256':
        digest_mod = hashlib.sha256
    elif alg == 'HS384':
        digest_mod = hashlib.sha384
    elif alg == 'HS512':
        digest_mod = hashlib.sha512
    else:
        raise ValueError(f"Unsupported alg: {alg}")

    hm = hmac.new(key.encode('utf-8'), data.encode('utf-8'), digest_mod)
    sig = base64.urlsafe_b64encode(hm.digest()).decode('utf-8').rstrip('=')
    return sig


def timer_thread():
    global running, candidate, start_time
    while running:
        elapsed = time.time() - start_time
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = int(elapsed % 60)
        hundredths = int((elapsed - int(elapsed)) * 100)
        sys.stdout.write(
            f"⏱  Trying      : {candidate:<30} Time elapsed  : {hours:03d}:{minutes:02d}:{seconds:02d}.{hundredths:02d}\r"
        )
        sys.stdout.flush()
        time.sleep(0.1)


def brute_force(signing_input, target_sig, alg, length, pos, current):
    global candidate
    if pos == length:
        candidate = ''.join(current)
        test_sig = hmac_base64url(signing_input, candidate, alg)
        return test_sig == target_sig
    for c in CHARSET:
        current[pos] = c
        if brute_force(signing_input, target_sig, alg, length, pos + 1, current):
            return True
    return False


def main():
    global running, start_time
    jwt = input("Enter JWT token\t		: ").strip()
    try:
        max_length = int(input("Enter max secret length to try\t: ").strip())
    except ValueError:
        print("Invalid length input.")
        return

    parts = jwt.split('.')
    if len(parts) != 3:
        print("Invalid JWT format.")
        return

    header_b64, payload_b64, signature_b64 = parts

    # Decode header
    # Add padding if necessary
    padded = header_b64 + '=' * (-len(header_b64) % 4)
    header_json_str = base64.urlsafe_b64decode(padded).decode('utf-8')
    alg = extract_alg_from_header(header_json_str)
    if not alg:
        print("Failed to extract alg from header.")
        return

    signing_input = f"{header_b64}.{payload_b64}"

    # Start timer
    start_time = time.time()
    t = threading.Thread(target=timer_thread)
    t.daemon = True
    t.start()

    # Brute-force
    for length in range(1, max_length + 1):
        if brute_force(signing_input, signature_b64, alg, length, 0, [''] * length):
            running = False
            total = time.time() - start_time
            print(f"\n✅ Found secret!   : {candidate:<30} Total time  : {total:.2f} seconds")
            return

    running = False
    total = time.time() - start_time
    print(f"\n❌ Secret not found. Total time  : {total:.2f} seconds")


if __name__ == '__main__':
    main()
