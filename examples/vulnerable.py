import os
import hashlib
import sqlite3

password = "admin123"
api_key = "SECRET_API_KEY"

user_input = input("Enter expression: ")
result = eval(user_input)

command = input("Enter command: ")
os.system(command)

hashed_password = hashlib.md5(password.encode()).hexdigest()

username = input("Enter username: ")

connection = sqlite3.connect("users.db")
cursor = connection.cursor()

query = "SELECT * FROM users WHERE username = '" + username + "'"

cursor.execute(query)
password_from_function = get_password()