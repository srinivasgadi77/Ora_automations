#!/usr/local/python3/bin/python3.6
import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode
import pytz
from datetime import datetime
import argparse

def insert_record( Pid, State, Hostname, Result):
    try:
        connection = mysql.connector.connect(
            host='10.245.254.60',
            database='jcmate_db',
            user='django_amdin',
            password='Django@123')

        # if output/result more than 450 chars, take onlt last line.
        if len(Result) > 450:
            Result = Result.split('\n')[-1]

        mySql_update_query = """UPDATE fixit_hostlist
                                SET State = "%s", Result = "%s"
                                WHERE Pid = %s AND Hostname = "%s" """ % ( State, Result.strip(), Pid, Hostname.strip() )

        print(mySql_update_query)

        cursor = connection.cursor()
        cursor.execute(mySql_update_query)

        connection.commit()
        print("Pid: %s Record inserted successfully into JCMate DB." % Pid)
        cursor.close()

    except mysql.connector.Error as error:
        print("Failed to insert record into JCMate table {}".format(error))

    finally:
        if (connection.is_connected()):
            connection.close()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Insert table attributes')

    parser.add_argument('--Pid', action="store", help ='PID of the record')
    parser.add_argument('--State', action="store", help='Process state')
    parser.add_argument('--Hostname', action="store", help='target name')
    parser.add_argument('--Result', action="store", help='Outcome')

    args = parser.parse_args()

    insert_record(args.Pid, args.State, args.Hostname, args.Result)

