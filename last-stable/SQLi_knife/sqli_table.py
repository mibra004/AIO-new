# simple calss to represent DB model
# consists of name, columns and rows and method to assing values
class Table:
    def __init__(self, name):
        self.table_name = name
        self.table_columns = []
        self.table_rows = []

    # set columns to table
    def set_tb_columns(self, columns):
        self.table_columns = columns

    # set data to table

    def set_tb_data(self, rows):
        self.table_rows = rows
