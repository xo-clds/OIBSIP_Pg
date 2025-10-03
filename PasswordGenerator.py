import tkinter as tk
from tkinter import messagebox
import string
import secrets
import os

def password_strength_label(password):
    length = len(password)
    pool_size = 0
    if any(c.islower() or c.isupper() for c in password):
        pool_size += 52  
    if any(c.isdigit() for c in password):
        pool_size += 10  
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)  

    #strength estimate
    if length < 6 or pool_size < 10:
        return "Weak "
    elif length < 10 or pool_size < 30:
        return "Medium "
    else:
        return "Strong "

def generate_password():
    length = length_var.get()
    use_letters = letters_var.get()
    use_numbers = numbers_var.get()
    use_symbols = symbols_var.get()

    char_pool = ""
    if use_letters: char_pool += string.ascii_letters
    if use_numbers: char_pool += string.digits
    if use_symbols: char_pool += string.punctuation

    if not char_pool:
        messagebox.showerror("Error", "Please select at least one character type.")
        return
    if length < 4:
        messagebox.showerror("Error", "Password length must be at least 4.")
        return

    password = ''.join(secrets.choice(char_pool) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

    #strength label
    strength = password_strength_label(password)
    strength_label.config(text=f"Strength: {strength}")

    # Save password if remember me is checked
    if remember_var.get():
        with open("saved_password.txt", "w") as f:
            f.write(password)

def copy_password():
    pwd = password_entry.get()
    if pwd:
        root.clipboard_clear()
        root.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy.")

def load_saved_password():
    if os.path.exists("saved_password.txt"):
        with open("saved_password.txt", "r") as f:
            saved_pwd = f.read().strip()
            if saved_pwd:
                password_entry.delete(0, tk.END)
                password_entry.insert(0, saved_pwd)
                strength = password_strength_label(saved_pwd)
                strength_label.config(text=f"Strength: {strength}")
                remember_var.set(True)

root = tk.Tk()
root.title(" Random Password Generator")
root.geometry("400x350")
root.resizable(False, False)
root.config(cursor="hand2")  


length_var = tk.IntVar(value=12)
letters_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)
remember_var = tk.BooleanVar(value=False)

tk.Label(root, text="Random Password Generator", font=("Arial", 16, "bold")).pack(pady=10)

tk.Label(root, text="Password Length:").pack()
tk.Spinbox(root, from_=4, to=50, textvariable=length_var, width=5, cursor="hand2").pack()

tk.Checkbutton(root, text="Include Letters (a-z, A-Z)", variable=letters_var, cursor="hand2").pack(anchor="w", padx=40)
tk.Checkbutton(root, text="Include Numbers (0-9)", variable=numbers_var, cursor="hand2").pack(anchor="w", padx=40)
tk.Checkbutton(root, text="Include Symbols (!@#$...)", variable=symbols_var, cursor="hand2").pack(anchor="w", padx=40)

generate_btn = tk.Button(root, text="Generate Password", command=generate_password, bg="lightblue", cursor="hand2")
generate_btn.pack(pady=10)

password_entry = tk.Entry(root, width=40, font=("Arial", 12), cursor="hand2")
password_entry.pack(pady=5)

copy_btn = tk.Button(root, text="Copy to Clipboard", command=copy_password, bg="lightgreen", cursor="hand2")
copy_btn.pack(pady=5)

# Strength label
strength_label = tk.Label(root, text="", font=("Arial", 10, "italic"))
strength_label.pack(pady=5)

tk.Checkbutton(root, text="Remember this password", variable=remember_var, cursor="hand2").pack(pady=5)

load_saved_password()

root.mainloop()








