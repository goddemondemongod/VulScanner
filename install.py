import configparser
import os
import pymysql

from django.conf import settings
settings.configure()

conf = configparser.ConfigParser()
conf.read(os.getcwd() + "/" + "config.ini")
mysql_config = {  # for mysql and postgresql
        'host': conf.get('db', 'ip'),
        'port': int(conf.get('db', 'port')),
        'user': conf.get('db', 'uname'),
        'password': conf.get('db', 'passwd'),
        'database': conf.get('db', 'table'),
        "connect_timeout": 1
    }

if __name__ == '__main__':
    sql_file = open("install.sql", "rb")
    try:
        conn = pymysql.connect(**mysql_config)
        cursor = conn.cursor()
        for i in sql_file:
            result = (cursor.execute(i.strip().decode()))
            if not result == 1:
                print("[-]execute sql fail")
                break
        conn.commit()
        conn.close()
        print("[+]install pocs success")
    except Exception as e:
        print(e)
        print("[-]can't connect to mysql")
