from Backend.CryptoUtils import CryptoPaladin as cp
import logging
from Backend.Repository.SQLiteRepository import SQLiteRepository
# To-Do configure logging
LOGFILE = r"D:\MyFiles\side_projects\PythonPassManager\logs\PaladinVaultLogs.log"
KEYFILE = r"D:\MyFiles\side_projects\PythonPassManager\testdir\key.bin"
DB = r"D:\MyFiles\side_projects\PythonPassManager\testdir\Passwords.db"

logging.basicConfig(
    filename=LOGFILE,
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %I:%M:%S"
)

salt = bytes.fromhex('80549af386a45d5936ca9b15ed428ec1')

password = "test"
generate_result = cp.generate_key(password,salt=salt)
print("Key: ",generate_result[0])
print("Salt: ",generate_result[1])

cp.save_key(generate_result[0],generate_result[1],KEYFILE)

load_result = cp.load_key(KEYFILE)
print("Key: ",load_result[0].decode())
print("Salt: ",load_result[1])

cp.verify_key(input=password,key=load_result[0],salt=load_result[1])

derive_result = cp.derive_key(password,load_result[1])
new_hash = derive_result[1]
print("Key: ",cp.base64.b64encode(derive_result[0]))
print("Key len: ",len(derive_result[0]))


# Encryption

teststr = "this is a test"
print("Original:",teststr)
nonce , ciphertext, tag = cp.encrypt(teststr.encode(),derive_result[0])

byte_decrypted = cp.decrypt(key=derive_result[0],ciphertext=ciphertext,nonce=nonce,tag=tag)
print("Result:",byte_decrypted.decode())

# database

mydb = SQLiteRepository(maindb_path=DB,key=derive_result[0])

mydb.create_password_entry(service="test service",username="tester",password=ciphertext,nonce=nonce,tag=tag,link="google.com",note="testing")
pss = mydb.get_all_passwords()
for p in pss:
    print(p.service)
    print(p.username)