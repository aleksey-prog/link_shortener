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
"link_source" TEXT, "link_short" TEXT, "flag" INTEGER NOT NULL DEFAULT 0, "count" INTEGER DEFAULT 0, PRIMARY KEY("id" 
AUTOINCREMENT));''')
conn.commit()
conn.close()


def get_hash(lk):
    return urlsafe_b64encode(hashlib.sha1(str(lk).encode()).digest()).decode()[0:12]


def login_check(username, user_password):
    con = sq.connect('links.db')
    cur = con.cursor()
    cur.execute('''SELECT password FROM users WHERE login = (?)''', (username,))
    data = cur.fetchall()
    con.close()
    if data[0][0] == hashlib.sha256(user_password.encode('utf-8')).hexdigest():
        return True
    else:
        return False


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
    if login_check(request.authorization['username'], request.authorization['password']):
        con = sq.connect('links.db')
        cur = con.cursor()
        cur.execute('''INSERT INTO links (login, link_source, link_short, flag) VALUES (?,?,?,?)''',
                    (request.authorization['username'], request.form['link'], get_hash(request.form['link']),
                     request.form['flag'],))
        con.commit()
        con.close()


@app.route('/<link_id>')
def url_redirect(link_id):
    con = sq.connect('links.db')
    cur = con.cursor()
    cur.execute('''SELECT link_source, count, flag, login FROM links WHERE link_short = (?)''', (link_id,))
    data = cur.fetchall()
    link_redirect = data[0][0]
    link_counter = data[0][1]
    flag = data[0][2]
    login = data[0][3]
    con.close()
    if flag == 0:
        if login_check(request.authorization['username'], request.authorization['password'])\
                and login == request.authorization['username']:
            con = sq.connect('links.db')
            cur = con.cursor()
            cur.execute('''UPDATE links SET count = ? WHERE link_short = (?)''', (link_counter + 1, link_id,))
            con.commit()
            con.close()
            return redirect(link_redirect)
    elif flag == 1:
        if login_check(request.authorization['username'], request.authorization['password']):
            con = sq.connect('links.db')
            cur = con.cursor()
            cur.execute('''UPDATE links SET count = ? WHERE link_short = (?)''', (link_counter + 1, link_id,))
            con.commit()
            con.close()
            return redirect(link_redirect)
    elif flag == 2:
        con = sq.connect('links.db')
        cur = con.cursor()
        cur.execute('''UPDATE links SET count = ? WHERE link_short = (?)''', (link_counter + 1, link_id,))
        con.commit()
        con.close()
        return redirect(link_redirect)


@app.route('/view_links', methods=['GET', 'POST'])
def view_link():
    if login_check(request.authorization['username'], request.authorization['password']):
        con = sq.connect('links.db')
        cur = con.cursor()
        cur.execute('''SELECT link_source FROM links WHERE login = (?)''', (request.authorization['username'],))
        data = cur.fetchall()
        con.close()
        for link in data:
            print(link[0])


@app.route('/delete_link', methods=['GET', 'POST'])
def delete_link():
    if login_check(request.authorization['username'], request.authorization['password']):
        con = sq.connect('links.db')
        cur = con.cursor()
        cur.execute('''DELETE FROM links WHERE login = (?) AND link_source = (?)''',
                    (request.authorization['username'], request.form['link'],))
        con.commit()
        con.close()


@app.route('/<user_name>/<link_id>')
def get_link_username(user_name, link_id):
    con = sq.connect('links.db')
    cur = con.cursor()
    cur.execute('''SELECT link_source, count, flag, login FROM links WHERE link_short = (?)''', (link_id,))
    data = cur.fetchall()
    link_redirect = data[0][0]
    link_counter = data[0][1]
    flag = data[0][2]
    login = data[0][3]
    con.close()
    if flag == 0:
        if login_check(request.authorization['username'], request.authorization['password']) \
                and login == request.authorization['username']:
            con = sq.connect('links.db')
            cur = con.cursor()
            cur.execute('''UPDATE links SET count = ? WHERE link_short = (?)''', (link_counter + 1, link_id,))
            con.commit()
            con.close()
            return redirect(link_redirect)
    elif flag == 1:
        if login_check(request.authorization['username'], request.authorization['password']):
            con = sq.connect('links.db')
            cur = con.cursor()
            cur.execute('''UPDATE links SET count = ? WHERE link_short = (?)''', (link_counter + 1, link_id,))
            con.commit()
            con.close()
            return redirect(link_redirect)
    elif flag == 2:
        con = sq.connect('links.db')
        cur = con.cursor()
        cur.execute('''UPDATE links SET count = ? WHERE link_short = (?)''', (link_counter + 1, link_id,))
        con.commit()
        con.close()
        return redirect(link_redirect)


if __name__ == '__main__':
    app.run()
