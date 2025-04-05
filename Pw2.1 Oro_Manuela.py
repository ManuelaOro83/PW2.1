import os
import base64
import sqlite3
import random
import pandas as pd
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def make_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def cifra_file(input_file, output_file):
    try:
        password = input("Inserisci la password per cifrare il file: ")
        salt = os.urandom(16)
        key = make_password(password, salt)
        cipher_suite = Fernet(key)

        with open(input_file, "rb") as f:
            file_data = f.read()

        encrypted_data = cipher_suite.encrypt(file_data)
        with open(output_file, "wb") as f:
            f.write(salt + encrypted_data)

        os.remove(input_file)
        print(f" File '{input_file}' cifrato e salvato come '{output_file}'.")
    except Exception as e:
        print(f" Errore durante la cifratura: {e}")

def decifra_file(input_file, output_file, password):
    try:
        with open(input_file, "rb") as f:
            file_data = f.read()

        salt = file_data[:16]
        encrypted_data = file_data[16:]
        key = make_password(password, salt)
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        print(f" File '{input_file}' decifrato e salvato come '{output_file}'.")
    except Exception as e:
        print(f" Errore durante la decrittazione: {e}")

def genera_email(nome, cognome):
    domini = ["gmail.com", "hotmail.com", "libero.it"]
    return f"{nome.lower()}.{cognome.lower()}{random.randint(1, 100)}@{random.choice(domini)}"

def genera_telefono():
    return f"+39 3{random.randint(10, 99)} {random.randint(1000000, 9999999)}"

def genera_utenti():
    utenti = []
    try:
        with open("nomi.txt", "r") as file_nomi, open("cognomi.txt", "r") as file_cognomi:
            nomi = [line.strip() for line in file_nomi]
            cognomi = [line.strip() for line in file_cognomi]
    except Exception as e:
        print(f" Errore nella lettura dei file nomi/cognomi: {e}")
        return utenti

    for _ in range(10):
        nome = random.choice(nomi)
        cognome = random.choice(cognomi)
        email = genera_email(nome, cognome)
        telefono = genera_telefono()
        utenti.append({"Nome": nome, "Cognome": cognome, "Email": email, "Telefono": telefono})
    return utenti

def salva_in_excel(utenti):
    excel_file = "Tabella_utenti.xlsx"
    try:
        df = pd.DataFrame(utenti)
        df.to_excel(excel_file, index=False)
        print(f" File Excel in chiaro salvato come '{excel_file}'.")
    except Exception as e:
        print(f" Errore durante il salvataggio del file Excel: {e}")
        return

    while True:
        risposta = input("Se si desidera cifrare il file Excel, inserisci s per si o n per no. Ricorda che il file in chiaro verrà eliminato. ").strip().lower()
        if risposta in ['s', 'n']:
            break
        print("Risposta non valida. Inserisci 's' o 'n'.")

    if risposta == "s":
        cifra_file(excel_file, "Tabella_cifrata.xlsx")
    else:
        print("Il file in chiaro è stato mantenuto.")

def conversione_excel_dinamica(excel_file, db_file, table_name="utenti"):
    if not os.path.exists(excel_file):
        print(f" Il file '{excel_file}' non esiste.")
        return

    try:
        df = pd.read_excel(excel_file)
        print(f" File Excel '{excel_file}' letto con successo.")
    except Exception as e:
        print(f" Errore durante la lettura del file Excel: {e}")
        return

    if df.empty:
        print("Il file Excel è vuoto. Nessuna operazione effettuata.")
        return

    try:
        conn = sqlite3.connect(db_file)
        df.to_sql(table_name, conn, if_exists='replace', index=False)
        conn.close()

        print(f"\n Importazione completata:")
        print(f"- Database aggiornato: '{db_file}'")

    except Exception as e:
        print(f" Errore nel database: {e}")

def menu():
    utenti = genera_utenti()
    print("Generati automaticamente 10 utenti.")
    salva_in_excel(utenti)

    while True:
        print("\nScegli un'opzione:")
        print("1. Decifrare il file Excel")
        print("2. Importare il file Excel nel DB")
        print("3. Decifrare il database SQLite")
        print("4. Esci")

        scelta = input("Inserisci il numero dell'opzione: ")

        excel_file = "Tabella_utenti.xlsx"
        encrypted_file = "Tabella_cifrata.xlsx"
        db_file = "DBMS_importato.sqlite"
        encrypted_db = "DBMS_cifrata.sqlite"
        decrypted_db = "DBMS_chiaro.sqlite"

        if scelta == "1":
            if os.path.exists(encrypted_file):
                password = input("Inserisci la password per decifrare il file Excel: ")
                decifra_file(encrypted_file, excel_file, password)
            else:
                print(f" Il file cifrato '{encrypted_file}' non esiste.")

        elif scelta == "2":
            if not os.path.exists(excel_file):
                print(f" Il file '{excel_file}' non esiste.")
                risposta = input("Se si desidera decifrare il file Excel, inserisci s per si o n per no.").strip().lower()
                if risposta == "s":
                    if os.path.exists(encrypted_file):
                        password = input("Inserisci la password per decifrare il file: ")
                        decifra_file(encrypted_file, excel_file, password)
                    else:
                        print(f" Il file cifrato '{encrypted_file}' non esiste.")
                        continue
                else:
                    print("Importazione annullata: il file Excel non è stato decriptato.")
                    continue

            conversione_excel_dinamica(excel_file, db_file)

            while True:
                risposta_db = input("Se si desidera cifrare il file SQLite, inserisci s per si o n per no. Ricorda che il file in chiaro verrà eliminato. (s/n): ").strip().lower()
                if risposta_db in ['s', 'n']:
                    break
                print("Risposta non valida. Inserisci 's' o 'n'.")

            if risposta_db == 's':
                cifra_file(db_file, encrypted_db)
            else:
                print("Il database SQLite in chiaro è stato mantenuto.")

        elif scelta == "3":
            if os.path.exists(encrypted_db):
                password = input("Inserisci la password per decifrare il database: ")
                decifra_file(encrypted_db, decrypted_db, password)
            else:
                print(f"Il file '{encrypted_db}' non esiste.")

        elif scelta == "4":
            print("Uscita dal programma.")
            break

        else:
            print("Opzione non valida.")

if __name__ == "__main__":
    menu()
