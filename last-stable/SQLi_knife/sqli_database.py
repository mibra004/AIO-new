# very simle class to represent DB model
# Name, tables, no more
class Database:
    def __init__(self, name):
        self.db_name = name
        self.db_tables = []

    def set_db_tables(self, table):
        self.db_tables = table
