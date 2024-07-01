import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, simpledialog, messagebox
import getpass
import hashlib
import os

class NoteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("My Diary")
        self.configure(background='#fff')
        self.geometry("600x400")

        # Initialize password variables
        # Variable to track if password protection is enabled
        self.password_protected = tk.BooleanVar(value=True)
        self.password = None
        self.password_file = "password.txt"  # File to store hashed password

         # Check if password file exists and load password if it does
        if os.path.exists(self.password_file):
            with open(self.password_file, "r") as f:
                self.password = f.read().strip()
                if self.password:
                    self.password_protected.set(True)
        else:
            self.password_protected = tk.BooleanVar(value=False)
            self.set_password()
            

        self.create_widgets()

    def create_widgets(self):

        #create a menu bar
        self.menu_bar  = tk.Menu(self)
        self.config(menu = self.menu_bar)

        #create a "File" menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Save File", command=self.save_file)
        self.menu_bar.add_command(label="New Tab", command=self.create_new_tab)

        # Add a Checkbutton to enable password protection
        self.menu_bar.add_checkbutton(label="Enable Password Protection", variable=self.password_protected, command=self.toggle_password)

        # add Notebook widget that will hold the tabs.
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, pady=5, padx=5)

        # create the first tab
        self.text_areas = []
        self.create_new_tab()

        # Prompt for password if enabled
        if self.password_protected.get():
            self.prompt_password()
        

    # Create a function to create a new tab
    def create_new_tab(self):
        new_tab = ttk.Frame(self.notebook) 
        self.notebook.add(new_tab, text="New Tab")

        text_area = scrolledtext.ScrolledText(new_tab, wrap=tk.WORD, width=80, height=20, font=('Segoi UI Emoji', 12))

        text_area.pack(expand=True, fill='both', pady=5, padx=5)

        text_area.configure(background='#fff')
        text_area.configure(highlightthickness=1, highlightbackground="gray", highlightcolor="gray")
        text_area.configure(insertbackground="blue")

        # modify to add "save" button to each tab
        save_button = ttk.Button(new_tab, text="Save", command=lambda: self.save_file(text_area))
        save_button.pack(pady=5, padx=5)

        # store the text_area object in a list
        self.text_areas.append(text_area)


    def save_file(self):
        # Get the currently selected tab
        current_tab = self.notebook.select()
        index = self.notebook.index(current_tab)

        text_area = self.text_areas[index]

        # Create a file dialog to prompt the user to select a file location
        file_dialog = filedialog.asksaveasfilename(defaultextension=".txt")

        # If the user selects a file location, save the text to that file
        if file_dialog:
            with open(file_dialog, "w") as file:
                file.write(text_area.get("1.0", tk.END))

    def set_password(self):
        new_password = simpledialog.askstring("Set Password", "Enter new password:", show='*')
        if new_password:
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            with open(self.password_file, "w") as f:
                f.write(hashed_password)

        self.password = hashed_password
        self.password_protected.set(True)
        print("password set successfully")

    def toggle_password(self):
        current_password = simpledialog.askstring("Verify Password", "Enter current password:", show='*')
        if current_password:
            entered_password_hash = hashlib.sha256(current_password.encode()).hexdigest()
            if entered_password_hash == self.password:
                if not self.password_protected.get():
                    self.password = None
                if os.path.exists(self.password_file):
                    os.remove(self.password_file)
                    self.password_protected.set(False)
                    print("password protection disabled")
            else:
                messagebox.showinfo("IncorrectPassword", "Cannot Disable Password Protection")

        


    def prompt_password(self):
        password_entry = tk.simpledialog.askstring("Password", "Enter your password:", show='*')
        if password_entry:
            entered_password_hash = hashlib.sha256(password_entry.encode()).hexdigest()
            if entered_password_hash == self.password:
                print("Password accepted. Access granted!")
                # Continue launching the application
        else:
            print("Incorrect password. Access denied.")
            self.destroy()


if __name__ == "__main__":
    app = NoteApp()
    app.mainloop()
