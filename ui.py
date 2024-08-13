import parallel_image_encryption
from tkinter import Tk, Label, Button, Entry, filedialog, StringVar, messagebox
import tkinter as tk
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox
from Crypto.Random import get_random_bytes



gkey = get_random_bytes(16)
class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryptor/Decryptor")

        self.encryption_key_var = StringVar()
        self.decryption_key_var = StringVar()
        self.s_decryption_key_var = StringVar()
        self.s_decryption_key_var = ''


        self.input_folder_var = StringVar()
        self.output_folder_var = StringVar()
        self.input_d_folder_var = StringVar()
        self.output_d_folder_var = StringVar()

        Label(root, text="AES Key (16 bytes):").grid(row=0, column=0, sticky="e")
        self.key_entry = Entry(root, textvariable=self.encryption_key_var, width=50)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)

        Label(root, text="Input Folder:").grid(row=1, column=0, sticky="e")
        self.input_folder_entry = Entry(root, textvariable=self.input_folder_var, width=50)
        self.input_folder_entry.grid(row=1, column=1, padx=5, pady=5)
        Button(root, text="Browse", command=self.browse_input_folder).grid(row=1, column=2, padx=5, pady=5)

        Label(root, text="Output Folder:").grid(row=2, column=0, sticky="e")
        self.output_folder_entry = Entry(root, textvariable=self.output_folder_var, width=50)
        self.output_folder_entry.grid(row=2, column=1, padx=5, pady=5)
        Button(root, text="Browse", command=self.browse_output_folder).grid(row=2, column=2, padx=5, pady=5)

        Button(root, text="Encrypt", command=self.encrypt).grid(row=3, column=0, columnspan=3, pady=10)

        Label(root, text="enter decryption key:").grid(row=5, column=0, sticky="e")
        self.key_entry = Entry(root, textvariable=self.decryption_key_var, width=50)
        self.key_entry.grid(row=5, column=1, padx=5, pady=5)
        Label(root, text=" or ").grid(row=5, column=1, sticky="e")

        Button(root, text="select key", command=self.select_key).grid(row=5, column=2, columnspan=3, pady=10)
        Label(root, text="Input Folder:").grid(row=6, column=0, sticky="e")
        self.input_d_folder_entry = Entry(root, textvariable=self.input_d_folder_var, width=50)
        self.input_d_folder_entry.grid(row=6, column=1, padx=5, pady=5)
        Button(root, text="Browse", command=self.browse_d_input_folder).grid(row=6, column=2, padx=5, pady=5)

        Label(root, text="Output Folder:").grid(row=7, column=0, sticky="e")
        self.output_d_folder_entry = Entry(root, textvariable=self.output_d_folder_var, width=50)
        self.output_d_folder_entry.grid(row=7, column=1, padx=5, pady=5)
        Button(root, text="Browse", command=self.browse_d_output_folder).grid(row=7, column=2, padx=5, pady=5)

        Button(root, text="Decrypt", command=self.decrypt).grid(row=8, column=0, columnspan=3, pady=10)


    def browse_input_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.input_folder_var.set(folder)

    def browse_output_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.output_folder_var.set(folder)

    def browse_d_input_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.input_d_folder_var.set(folder)

    def browse_d_output_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.output_d_folder_var.set(folder)
    def select_key(self):
        key_path = filedialog.askopenfilename(title="Select Key File")
        if not key_path:
                return
        else:
            with open(key_path, "rb") as key_file:
                self.s_decryption_key_var = key_file.read()
                self.decryption_key_var.set(self.s_decryption_key_var)
                print(self.s_decryption_key_var)
    def clear_key(self):
        self.s_decryption_key_var = ''
        # self.decryption_key_var.set('')
        return


    def encrypt(self):
        key = self.encryption_key_var.get().encode()
        print(key)
        if not key:
            key = gkey
            print(key)
        else:
            if len(key) != 16:
                messagebox.showerror("Error", "Key must be 16 bytes long.")
                return

        input_folder = self.input_folder_var.get()
        output_folder = self.output_folder_var.get()
        parallel_image_encryption.encrypt_files_in_folder(input_folder, output_folder, key)
        messagebox.showinfo("Success", "Encryption completed.")
        with open(output_folder + "/encryption_key.key", "wb") as key_file:
            key_file.write(key)
        messagebox.showinfo("Success",
                            f"Image encrypted successfully!\nKey: {key}\nand saved as {output_folder}\nKey saved as {output_folder}.key")
        # self.encryption_key_var.set('')

    def decrypt(self):
        key = self.s_decryption_key_var
        if not key:
            key = self.decryption_key_var.get().encode()
            print(self.decryption_key_var)
            if not key:
                messagebox.showinfo("error", "enter decryption key")
                return
        input_folder = self.input_d_folder_var.get()
        output_folder = self.output_d_folder_var.get()
        parallel_image_encryption.decrypt_files_in_folder(input_folder, output_folder, key)
        messagebox.showinfo("Success", "Decryption completed.")

        self.clear_key()
if __name__ == "__main__":
    root = Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()