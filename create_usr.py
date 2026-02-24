import hashlib
import secrets

pw = input("Kullanıcı Şifresini Giriniz: ")
hash_object = hashlib.sha256(pw.encode('utf-8'))
psw = hash_object.hexdigest()

token = secrets.token_hex(16)

print(f"Kullanicinin Hash'li Şifresi: {psw}")
print(f"Kullanininin Guvenli Tokeni: {token}")