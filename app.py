import sqlite3 as sq
import hashlib
from base64 import urlsafe_b64encode
from flask import Flask, request, redirect

app = Flask(__name__)

conn = sq.connect('links.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE if NOT EXISTS "users" ("id" INTEGER NOT NULL UNIQUE, "login"	TEXT NOT NULL UNIQUE, 
"password" TEXT NOT NULL, PRIMARY KEY("id" AUTOINCREMENT));''')
cursor.execute('''CREATE TABLE if NOT EXISTS "links" ("id" INTEGER NOT NULL UNIQUE, "login"	TEXT NOT NULL, 
"link_source" TEXT, "link_short" TEXT, "flag" INTEGER NOT NULL DEFAULT 0, PRIMARY KEY("id" 
AUTOINCREMENT));''')
conn.commit()
conn.close()


def get_hash(lk):
    return urlsafe_b64encode(hashlib.sha1(str(lk).encode()).digest()).decode()[0:12]


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/register', methods=['GET', 'POST'])
def reg_user():
    con = sq.connect('links.db')
    cur = con.cursor()
    pass_hash = hashlib.sha256(request.authorization['password'].encode('utf-8'))
    try:
        cur.execute('''INSERT INTO users (login, password) VALUES (?,?)''',
                    (request.authorization['username'], pass_hash.hexdigest(),))
        con.commit()
    except sq.IntegrityError:
        print('Пользователь уже зарегестрирован')

    con.close()


@app.route('/add_link', methods=['GET', 'POST'])
def add_link():
    con = sq.connect('links.db')
    cur = con.cursor()
    cur.execute('''SELECT password FROM users WHERE login = (?)''', (request.authorization['username'],))
    data = cur.fetchall()
    con.close()
    if data[0][0] == hashlib.sha256(request.authorization['password'].encode('utf-8')).hexdigest():
        con = sq.connect('links.db')
        cur = con.cursor()
        cur.execute('''INSERT INTO links (login, link_source, link_short) VALUES (?,?,?)''',
                    (request.authorization['username'], request.form['link'], get_hash(request.form['link']),))
        con.commit()
        con.close()


@app.route('/<link_id>')
def url_redirect(link_id):
    con = sq.connect('links.db')
    cur = con.cursor()
    cur.execute('''SELECT link_source FROM links WHERE link_short = (?)''', (link_id,))
    data = cur.fetchall()
    con.close()
    return redirect(data[0][0])


if __name__ == '__main__':
    app.run()
