import os
import json
import hashlib

from devices.iot_device import IoTDevice
from server.cloud_server import CloudServer


HASH_DATABASE = "file_hashes.json"


def calculate_hash(file_path):
    hasher = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(64 * 1024)

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


def load_hash_database():
    if not os.path.exists(HASH_DATABASE):
        return {}

    with open(HASH_DATABASE, "r") as f:
        return json.load(f)


def save_hash_database(database):
    with open(HASH_DATABASE, "w") as f:
        json.dump(database, f, indent=4)


def main():

    print("=" * 60)
    print("       FILE INTEGRITY VERIFICATION SYSTEM")
    print("=" * 60)

    file_path = input("\nEnter the full path of your file: ").strip()

    if not os.path.isfile(file_path):
        print("\n❌ File not found!")
        return

    # Convert path to an absolute path
    file_path = os.path.abspath(file_path)

    print("\n✅ File found")
    print("File:", file_path)

    # -------------------------------------------------
    # STEP 1: Calculate current file hash
    # -------------------------------------------------

    current_hash = calculate_hash(file_path)

    print("\nCurrent SHA-256:")
    print(current_hash)

    # -------------------------------------------------
    # STEP 2: Load previously stored hashes
    # -------------------------------------------------

    database = load_hash_database()

    # -------------------------------------------------
    # FIRST TIME CHECK
    # -------------------------------------------------

    if file_path not in database:

        print("\n🆕 This file has not been registered before.")

        database[file_path] = current_hash

        save_hash_database(database)

        print("✅ Original hash stored successfully.")

    # -------------------------------------------------
    # EXISTING FILE CHECK
    # -------------------------------------------------

    else:

        original_hash = database[file_path]

        print("\nOriginal SHA-256:")
        print(original_hash)

        if current_hash == original_hash:

            print("\n✅ INTEGRITY VERIFIED")
            print("The file has NOT been modified.")

        else:

            print("\n🚨 FILE MODIFIED!")
            print("The current hash does NOT match the original hash.")

            print("\nExpected:")
            print(original_hash)

            print("\nFound:")
            print(current_hash)

    # -------------------------------------------------
    # BLS VERIFICATION
    # -------------------------------------------------

    device = IoTDevice("file-device-001")

    cloud = CloudServer()

    cloud.provision_device(device)

    envelope = device.send_file(file_path)

    print("\n[Device] File signed with BLS")

    result = cloud.receive(envelope)

    print("\n=== BLS VERIFICATION ===")

    if result.accepted:
        print("✅ BLS verification: ACCEPTED")
    else:
        print("❌ BLS verification: REJECTED")
        print("Reason:", result.reason.value)

    print("\n" + cloud.status_report())


if __name__ == "__main__":
    main()