import getpass
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sqlite3
import bcrypt

DEFAULT_PASS = os.path.join(os.path.dirname(__file__), 'chameleo-pass.sqlite3')
salt = b"$2b$12$2.YKtMpxs7BI8kGbGc41XOkBm3KROp64ARJHbz.OeM4QSuF.NBlRy"
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=10000,
    backend=default_backend()
)

def requestPassword():
    correctPassword = 'bean'
    key = getpass.getpass()
    print(key)

    if key == correctPassword:
        return True
    return False

def dbConnect(db_path=DEFAULT_PASS):
    con = sqlite3.connect(db_path)
    return con

def createAccount():
    print("Creating account...")
    new_pass = "a"
    confirm_pass = "b"
    while new_pass != confirm_pass:
        new_pass = getpass.getpass("New Password: ")
        confirm_pass = getpass.getpass("Confirm Password: ")
        if new_pass != confirm_pass:
            print("Passwords don't match")
    print("Creating database...")
    db_con = dbConnect()
    db_cur = db_con.cursor()
    print("Creating tables...")
    create_table_sql = """CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY AUTOINCREMENT, password TEXT NOT NULL)"""
    db_cur.execute(create_table_sql)
    create_table_sql = """CREATE TABLE IF NOT EXISTS 
    passwords(
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        user_id INTEGER NOT NULL, 
        name TEXT NOT NULL, 
        password TEXT NOT NULL
    )"""
    
    db_cur.execute(create_table_sql)
    print("Creating account")
    hashed_pass = bcrypt.hashpw(str.encode(new_pass), bcrypt.gensalt())
    insert_user_sql = "INSERT INTO user (password) VALUES (?)"
    db_cur.execute(insert_user_sql, (hashed_pass.decode(),))
    db_con.commit()
    print("Password added")
    db_con.close()
    print("Account created\n")

def loginAccount():
    password = getpass.getpass("Password: ")
    db_con = dbConnect()
    db_cur = db_con.cursor()
    select_alluser_sql = "SELECT * FROM user"
    db_cur.execute(select_alluser_sql)
    users = db_cur.fetchall()
    for user in users:
        if bcrypt.checkpw(str.encode(password), str.encode(user[1])):
            db_con.close()
            return user
    db_con.close()
    return 0

def deleteAccount():
    print("Enter password to delete that account")
    user_id = loginAccount()
    if user_id:
        db_con = dbConnect()
        db_cur = db_con.cursor()
        delete_user_sql = "DELETE FROM user WHERE id = ?"
        db_cur.execute(delete_user_sql, (user_id,))
        db_con.commit()
        db_con.close()
        return 1
    return 0

def getAllNames(user_id):
    db_con = dbConnect()
    db_cur = db_con.cursor()
    select_name_sql = "SELECT name FROM passwords WHERE user_id = ?"
    db_cur.execute(select_name_sql, (user_id,))
    names = db_cur.fetchall()
    return names

def getPassword(user_id, user_password, key):
    cat_name = input("Name of the service (for example, YouTube): ")
    db_con = dbConnect()
    db_cur = db_con.cursor()
    print(cat_name)
    select_password_sql = "SELECT password FROM passwords WHERE name = ? AND user_id = ?"
    db_cur.execute(select_password_sql, (cat_name, user_id))
    hashed_passwordBytes = db_cur.fetchall()[0][0].encode()
    fern = Fernet(key)
    passwordBytes = fern.decrypt(hashed_passwordBytes)
    password = passwordBytes.decode() 

    db_con.commit()
    db_con.close()
    return password

def storePassword(user_id, user_password, key):
    cat_name = input("Name of the service (for example, YouTube): ")
    app_password = getpass.getpass("Password: ")

    db_con = dbConnect()
    db_cur = db_con.cursor()

    fern = Fernet(key)
    hashed_pass = fern.encrypt(app_password.encode())
    
    insert_password_sql = "INSERT INTO passwords(user_id, name, password) VALUES (?, ?, ?)"
    db_cur.execute(insert_password_sql, (user_id, cat_name, hashed_pass.decode()))
    db_con.commit()
    db_con.close()
    # regular_pass = fern.decrypt(hashed_pass)
    # print(regular_pass)

def editPassword(user_id, user_password, key):
    cat_name = input("Name of the service (for example, YouTube): ")
    app_password = getpass.getpass("Old Password: ")
    new_app_password = getpass.getpass("New Password: ")
    confirm_pass = getpass.getpass("Confirm New Password: ")
    if new_app_password != confirm_pass:
        print("New passwords don't match")
        return 0
    db_con = dbConnect()
    db_cur = db_con.cursor()
    fern = Fernet(key)

    select_password_sql = "SELECT * FROM passwords WHERE name = ?"
    db_cur.execute(select_password_sql, (cat_name,))
    passRecord = db_cur.fetchall()[0]

    decryptOldPass = fern.decrypt(passRecord[3].encode()).decode()
    print(decryptOldPass)
    if app_password != decryptOldPass:
        print("Old password incorrect")
        return 0
    update_password_sql = "UPDATE passwords SET password = ? WHERE name = ?"


    hashed_pass = fern.encrypt(new_app_password.encode()).decode()
    old_hashed_pass = fern.encrypt(app_password.encode()).decode()

    db_cur.execute(update_password_sql, (hashed_pass, cat_name))

    db_con.commit()
    db_con.close()
    return 1

    

    
user = tuple()

print("Welcome to chameleo-pass, a client only password vault")
print("ca - create account\nla - login account\nda - delete account")
while True:
    decision = input("> ")

    if decision == "ca":
        createAccount()

    if decision == "la":
        user = loginAccount()
        if user:
            print("Login successful...")
            break
        else:
            print("Incorrect password")

    if decision == "da":
        if deleteAccount():
            print("Successfully deleted account")
        else:
            print("Incorrect password")
print("Welcome to chameleo-pass, a client side only password vault")
print("store and edit passwords")
key = base64.urlsafe_b64encode(kdf.derive(user[1].encode()))
while True:
    print("gp - get password\ngn - get all names\nsp - store password\nep - edit password\nlo - log out")
    decision = input("> ")

    if decision == "gp":
        password = getPassword(user[0], user[1], key)
        if len(password) == 0:
            print("No password found with that name :(")

    if decision == "gn":
        print("Displaying all names stored: ")
        names = getAllNames(user[0])
        for i in range(len(names)):
            print(names[i][0])
        print("")

    if decision == "sp":
        storePassword(user[0], user[1], key)

    if decision == "ep":
        edit = editPassword(user[0], user[1], key)
        if edit:
            print("Successfully changed password")
        else:
            print("Wrong password")

    if decision == "lo":
        print("Logging out...")
        exit()
