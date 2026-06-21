import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib

# Database Setup
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password TEXT
)
""")
conn.commit()

# Hash Password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Register Function
def register():
    username = entry_username.get()
    password = entry_password.get()

    if username == "" or password == "":
        messagebox.showerror("Error", "Fill all fields")
        return

    hashed_password = hash_password(password)

    try:
        cursor.execute(
            "INSERT INTO users VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        messagebox.showinfo("Success", "Registration Successful")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists")

# Login Function
def login():
    username = entry_username.get()
    password = hash_password(entry_password.get())

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    user = cursor.fetchone()

    if user:
        messagebox.showinfo("Success", f"Welcome {username}")
        open_dashboard()
    else:
        messagebox.showerror("Error", "Invalid Username or Password")

# Dashboard Window
def open_dashboard():
    dashboard = tk.Toplevel(root)
    dashboard.title("Dashboard")
    dashboard.geometry("300x200")

    tk.Label(
        dashboard,
        text="Login Successful!",
        font=("Arial", 14)
    ).pack(pady=20)

    tk.Button(
        dashboard,
        text="Logout",
        command=dashboard.destroy
    ).pack()

# Main Window
root = tk.Tk()
root.title("Secure Login System")
root.geometry("350x250")

tk.Label(root, text="Username").pack(pady=5)
entry_username = tk.Entry(root)
entry_username.pack()

tk.Label(root, text="Password").pack(pady=5)
entry_password = tk.Entry(root, show="*")
entry_password.pack()

tk.Button(root, text="Register", command=register).pack(pady=10)
tk.Button(root, text="Login", command=login).pack()

root.mainloop()

conn.close()
input()
