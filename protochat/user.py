import mysql.connector
from os import urandom
from datetime import datetime
import pcutils

class User:

    _db_cnx = None


    @classmethod
    def set_db_cnx(cls, cnx):
        cls._db_cnx = cnx


    def __init__(self):
        self._id = pcutils.hex_id(8)
        self._username = None
        self._crypt_key = None
        self._bio = None
        self._profile_pic_id = None
        self._join_date = None
        self._last_seen = None

    
    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        self._id = id

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, username):
        self._username = username

    @property
    def crypt_key(self):
        return self._crypt_key

    @crypt_key.setter
    def crypt_key(self, crypt_key):
        self._crypt_key = crypt_key

    @property
    def bio(self):
        return self._bio

    @bio.setter
    def bio(self, bio):
        self._bio = bio

    @property
    def profile_pic_id(self):
        return self._profile_pic_id

    @profile_pic_id.setter
    def profile_pic_id(self, profile_pic_id):
        self._profile_pic_id = profile_pic_id

    @property
    def join_date(self):
        return self._join_date

    @join_date.setter
    def join_date(self, join_date):
        self._join_date = join_date

    @property
    def last_seen(self):
        return self._last_seen

    @last_seen.setter
    def last_seen(self, last_seen):
        self._last_seen = last_seen


    def valid(self):
        return (self._id is not None and self._username is not None and
            self._crypt_key is not None and self._bio is not None and
            self._profile_pic_id is not None and self._join_date is not None and
            self._last_seen is not None)


    def insert(self):
        try:
            t = (self._id, self._username, self._crypt_key, self._bio,
                    self._profile_pic_id, self._join_date, self._last_seen)
            cursor = type(self)._db_cnx.cursor()
            cursor.execute("INSERT INTO users \
                    (id, username, decryption_key, bio, profile_pic_id, join_date, last_seen) \
                    VALUES (%s, %s, %s, %s, %s, %s, %s)", t)
            type(self)._db_cnx.commit()
            return True
        except mysql.connector.Error as err:
            print("Unable to insert user")
            print(err)
            return False

