from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import numpy as np
import os
from Crypto.Util.Padding import pad
from concurrent.futures import ThreadPoolExecutor


def encrypt_image(input_image_path, output_folder, key):

    image = Image.open(input_image_path)
    image_data = np.array(image)
    image_data_bytes = image_data.tobytes()
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(image_data_bytes, AES.block_size))
    original_shape = image_data.shape
    encrypted_data = iv + np.array(original_shape, dtype=np.int32).tobytes() + ciphertext
    encrypted_length = len(encrypted_data)
    width = 256
    height = (encrypted_length + width - 1) // width
    padded_encrypted_data = encrypted_data.ljust(width * height, b'\0')
    encrypted_image = Image.frombytes('L', (width, height), padded_encrypted_data)
    base_name = os.path.basename(input_image_path)
    output_image_path = os.path.join(output_folder, os.path.splitext(base_name)[0] + '.png')
    encrypted_image.save(output_image_path)



def decrypt_image(input_image_path, decrypted_folder, key):
    encrypted_image = Image.open(input_image_path)
    encrypted_data = np.array(encrypted_image).tobytes()
    iv = encrypted_data[:16]  # First 16 bytes are the IV
    original_shape = np.frombuffer(encrypted_data[16:28], dtype=np.int32)
    ciphertext = encrypted_data[28:].rstrip(b'\0')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    image_data = np.frombuffer(plaintext, dtype=np.uint8).reshape(original_shape)


    base_name = os.path.basename(input_image_path)
    output_image_path = os.path.join(decrypted_folder, os.path.splitext(base_name)[0] + '.png')
    # Save the decrypted image
    decrypted_image = Image.fromarray(image_data)
    decrypted_image.save(output_image_path)


def encrypt_files_in_folder(folder_path, output_folder, key):
    print(f"Checking if output folder {output_folder} exists...")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder: {output_folder}")
    else:
        print(f"Output folder {output_folder} already exists.")

    print(f"Checking if input folder {folder_path} exists...")
    if not os.path.exists(folder_path):
        print(f"Error: The folder path {folder_path} does not exist.")
        return

    print(f"Input folder {folder_path} exists. Proceeding with encryption.")

    file_paths = [os.path.join(folder_path, file_name) for file_name in os.listdir(folder_path) if
                  os.path.isfile(os.path.join(folder_path, file_name))]

    with ThreadPoolExecutor() as executor:
        executor.map(lambda file_path: encrypt_image(file_path, output_folder, key), file_paths)


def decrypt_files_in_folder(folder_path, output_folder, key):
    print(f"Checking if output folder {output_folder} exists...")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        print(f"Created output folder: {output_folder}")
    else:
        print(f"Output folder {output_folder} already exists.")

    print(f"Checking if input folder {folder_path} exists...")
    if not os.path.exists(folder_path):
        print(f"Error: The folder path {folder_path} does not exist.")
        return

    print(f"Input folder {folder_path} exists. Proceeding with encryption.")

    file_paths = [os.path.join(folder_path, file_name) for file_name in os.listdir(folder_path) if
                  os.path.isfile(os.path.join(folder_path, file_name))]

    with ThreadPoolExecutor() as executor:
        executor.map(lambda file_path: decrypt_image(file_path, output_folder, key), file_paths)

#
# key = get_random_bytes(16)  # AES-128 key
# print(key)
# folder_path = "C:/Users/ALAMEEN/Desktop/images"
# output_folder = "C:/Users/ALAMEEN/Desktop/encrypted-imges"
# input_d_path = "C:/Users/ALAMEEN/Desktop/encrypted-imges"
# output_d_folder = "C:/Users/ALAMEEN/Desktop/decrypted-imges"
# encrypt_files_in_folder(folder_path, output_folder, key)
# decrypt_files_in_folder(input_d_path, output_d_folder, key)
#
# #

###################################################################
