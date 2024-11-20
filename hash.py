import hashlib
password = "mypassword"
salt = "unique_salt_value"
hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
print("Original password:", password)
print("Salt value:", salt)
print("Hashed password:", hashed_password)
