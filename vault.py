import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import base64
from cryptography.fernet import Fernet


# ── Encryption ──
def make_key(master: str) -> bytes:
    key = hashlib.sha256(master.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt(text, master):
    return Fernet(make_key(master)).encrypt(text.encode()).decode()

def decrypt(token, master):
    return Fernet(make_key(master)).decrypt(token.encode()).decode()


# ── Database ──
def init_db():
    conn = sqlite3.connect("vault.db")
    conn.execute('''CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT, username TEXT, password TEXT
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS master (
        id INTEGER PRIMARY KEY, hash TEXT
    )''')
    conn.commit()
    conn.close()

def get_conn():
    return sqlite3.connect("vault.db")

def get_master_hash():
    conn = get_conn()
    row = conn.execute("SELECT hash FROM master LIMIT 1").fetchone()
    conn.close()
    return row[0] if row else None

def set_master_hash(pw):
    h = hashlib.sha256(pw.encode()).hexdigest()
    conn = get_conn()
    conn.execute("DELETE FROM master")
    conn.execute("INSERT INTO master (hash) VALUES (?)", (h,))
    conn.commit()
    conn.close()

def verify_master(pw):
    return hashlib.sha256(pw.encode()).hexdigest() == get_master_hash()

def get_entries():
    conn = get_conn()
    rows = conn.execute("SELECT id, site, username FROM entries ORDER BY site").fetchall()
    conn.close()
    return rows

def add_entry(site, username, password, master):
    conn = get_conn()
    conn.execute("INSERT INTO entries (site, username, password) VALUES (?,?,?)",
                 (site, username, encrypt(password, master)))
    conn.commit()
    conn.close()

def delete_entry(entry_id):
    conn = get_conn()
    conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
    conn.commit()
    conn.close()

def get_password(entry_id, master):
    conn = get_conn()
    row = conn.execute("SELECT password FROM entries WHERE id=?", (entry_id,)).fetchone()
    conn.close()
    return decrypt(row[0], master) if row else ""


# ── GUI App ──
class VaultApp:
    def __init__(self, root, master_pw):
        self.root = root
        self.master_pw = master_pw
        self.root.title("🔐 VAULT - Password Manager")
        self.root.geometry("600x650")
        self.root.configure(bg="#1a1a2e")
        self.root.resizable(True, True)
        self.build_ui()
        self.load_entries()

    def build_ui(self):
        # Title
        tk.Label(self.root, text="🔐 VAULT", font=("Courier", 22, "bold"),
                 bg="#1a1a2e", fg="#00d4ff").pack(pady=(20, 5))
        tk.Label(self.root, text="Password Manager", font=("Courier", 10),
                 bg="#1a1a2e", fg="#555").pack()

        # Search
        search_frame = tk.Frame(self.root, bg="#1a1a2e")
        search_frame.pack(fill="x", padx=20, pady=(15, 5))
        tk.Label(search_frame, text="Search:", bg="#1a1a2e",
                 fg="#aaa", font=("Courier", 10)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *a: self.load_entries())
        tk.Entry(search_frame, textvariable=self.search_var,
                 bg="#0f3460", fg="white", insertbackground="white",
                 font=("Courier", 10), bd=0, relief="flat").pack(
                 side="left", fill="x", expand=True, padx=(8, 0), ipady=5)

        # Table
        frame = tk.Frame(self.root, bg="#1a1a2e")
        frame.pack(fill="both", expand=True, padx=20, pady=10)

        cols = ("Site", "Username")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=8)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background="#0f3460", foreground="white",
            rowheight=30, fieldbackground="#0f3460", font=("Courier", 10))
        style.configure("Treeview.Heading",
            background="#00d4ff", foreground="#1a1a2e",
            font=("Courier", 10, "bold"))
        style.map("Treeview", background=[("selected", "#16213e")])

        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=250)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#1a1a2e")
        btn_frame.pack(pady=10)

        buttons = [
            ("➕ Add",     "#00d4ff", "#1a1a2e", self.add_entry),
            ("👁 Reveal",  "#0f3460", "white",   self.reveal_password),
            ("📋 Copy",    "#0f3460", "white",   self.copy_password),
            ("🗑 Delete",  "#ff3c5a", "white",   self.delete_entry),
        ]

        for text, bg, fg, cmd in buttons:
            tk.Button(btn_frame, text=text, bg=bg, fg=fg,
                      font=("Courier", 10, "bold"), relief="flat",
                      padx=14, pady=8, cursor="hand2",
                      command=cmd).pack(side="left", padx=5)

    def load_entries(self):
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().lower()
        for row in get_entries():
            if query in row[1].lower() or query in row[2].lower():
                self.tree.insert("", "end", iid=row[0],
                                 values=(row[1], row[2]))

    def get_selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Please select an entry first.")
            return None
        return int(sel[0])

    def add_entry(self):
        win = tk.Toplevel(self.root)
        win.title("Add Entry")
        win.geometry("360x280")
        win.configure(bg="#1a1a2e")
        win.resizable(False, False)

        fields = {}
        for label in ["Site", "Username", "Password"]:
            tk.Label(win, text=label, bg="#1a1a2e", fg="#aaa",
                     font=("Courier", 10)).pack(anchor="w", padx=20, pady=(12, 2))
            show = "*" if label == "Password" else ""
            e = tk.Entry(win, bg="#0f3460", fg="white", insertbackground="white",
                         font=("Courier", 11), show=show, bd=0, relief="flat")
            e.pack(fill="x", padx=20, ipady=6)
            fields[label] = e

        def save():
            site = fields["Site"].get().strip()
            user = fields["Username"].get().strip()
            pw   = fields["Password"].get().strip()
            if not site or not user or not pw:
                messagebox.showerror("Error", "All fields are required!", parent=win)
                return
            add_entry(site, user, pw, self.master_pw)
            self.load_entries()
            win.destroy()

        tk.Button(win, text="SAVE", bg="#00d4ff", fg="#1a1a2e",
                  font=("Courier", 11, "bold"), relief="flat",
                  padx=20, pady=8, cursor="hand2",
                  command=save).pack(pady=16)

    def reveal_password(self):
        entry_id = self.get_selected_id()
        if entry_id:
            pw = get_password(entry_id, self.master_pw)
            messagebox.showinfo("Password", f"🔑  {pw}")

    def copy_password(self):
        entry_id = self.get_selected_id()
        if entry_id:
            pw = get_password(entry_id, self.master_pw)
            self.root.clipboard_clear()
            self.root.clipboard_append(pw)
            messagebox.showinfo("Copied", "✅ Password copied to clipboard!")

    def delete_entry(self):
        entry_id = self.get_selected_id()
        if entry_id:
            if messagebox.askyesno("Delete", "Are you sure you want to delete this entry?"):
                delete_entry(entry_id)
                self.load_entries()


# ── Login / Setup Window ──
def login_screen():
    root = tk.Tk()
    root.title("VAULT — Login")
    root.geometry("360x320")
    root.configure(bg="#1a1a2e")
    root.resizable(False, False)

    tk.Label(root, text="🔐", font=("Arial", 40),
             bg="#1a1a2e").pack(pady=(30, 5))
    tk.Label(root, text="VAULT", font=("Courier", 20, "bold"),
             bg="#1a1a2e", fg="#00d4ff").pack()

    is_setup = get_master_hash() is None
    subtitle = "Create master password" if is_setup else "Enter master password"
    tk.Label(root, text=subtitle, font=("Courier", 9),
             bg="#1a1a2e", fg="#555").pack(pady=(4, 16))

    pw_var = tk.StringVar()
    tk.Entry(root, textvariable=pw_var, show="*",
             bg="#0f3460", fg="white", insertbackground="white",
             font=("Courier", 13), bd=0, relief="flat",
             justify="center").pack(ipady=8, padx=40, fill="x")

    error_label = tk.Label(root, text="", font=("Courier", 9),
                           bg="#1a1a2e", fg="#ff3c5a")
    error_label.pack(pady=6)

    def submit():
        pw = pw_var.get().strip()
        if len(pw) < 4:
            error_label.config(text="⚠ Minimum 4 characters")
            return
        if is_setup:
            set_master_hash(pw)
            root.destroy()
            launch_app(pw)
        else:
            if verify_master(pw):
                root.destroy()
                launch_app(pw)
            else:
                error_label.config(text="⚠ Incorrect password")
                pw_var.set("")

    btn_text = "CREATE VAULT" if is_setup else "UNLOCK"
    tk.Button(root, text=btn_text, bg="#00d4ff", fg="#1a1a2e",
              font=("Courier", 11, "bold"), relief="flat",
              padx=20, pady=8, cursor="hand2",
              command=submit).pack(pady=10)

    root.bind("<Return>", lambda e: submit())
    root.mainloop()


def launch_app(master_pw):
    root = tk.Tk()
    VaultApp(root, master_pw)
    root.mainloop()


# ── Run ──
if __name__ == "__main__":
    init_db()
    login_screen()




## 📁 File 2: `requirements.txt`

cryptography