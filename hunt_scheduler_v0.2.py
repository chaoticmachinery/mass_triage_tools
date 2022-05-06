#!/usr/bin/python

# Velociraptor Hunt Scheduler
#
# The script will automatically schedule hunts based on a list. 
#
# Based on Velociraptor's client_example.py
# Code by: Keven Murphy
#
# Requires Python 3

import argparse
import json
import grpc
import time
import yaml
import csv
import pandas as pd

import pyvelociraptor
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

version = '0.2'


def run(config, query, env_dict, ocsv, ojson):
    # Fill in the SSL params from the api_client config file. You can get such a file:
    # velociraptor --config server.config.yaml config api_client > api_client.conf.yaml
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"))

    # This option is required to connect to the grpc server by IP - we
    # use self signed certs.
    options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)

    env = []
    for k, v in env_dict.items():
        env.append(dict(key=k, value=v))

    # The first step is to open a gRPC channel to the server..
    with grpc.secure_channel(config["api_connection_string"],
                             creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)

        # The request consists of one or more VQL queries. Note that
        # you can collect artifacts by simply naming them using the
        # "Artifact" plugin.
        request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            max_row=100,
            Query=[api_pb2.VQLRequest(
                Name="Test",
                VQL=query,
            )],
            env=env,
        )

        # This will block as responses are streamed from the./mass_triage.py  --config api_client.yaml --csv huntsimp.csv
        # server. If the query is an event query we will run this loop
        # forever.
        for response in stub.Query(request):
            if response.Response:
                # Each response represents a list of rows. The columns
                # are provided in their own field as an array, to
                # ensure column order is preserved if required. If you
                # dont care about column order just ignore the Columns
                # field. Note that although JSON does not specify the
                # order of keys in a dict Velociraptor always
                # maintains this order so an alternative to the
                # Columns field is to use a JSON parser that preserves
                # field ordering.

                print("Columns %s:" % response.Columns)

                # The actual payload is a list of dicts. Each dict has
                # column names as keys and arbitrary (possibly nested)
                # values.
                if ojson:
                   package = json.loads(response.Response)
                   print (package)
                   print ('\n\n')
    
                if ocsv:
                   df = pd.read_json(response.Response)
                   out = df.to_csv(sep = '|')
                   print(out)  
                   print ('\n\n')             

            elif response.log:
                # Query execution logs are sent in their own messages.
                print ("%s: %s" % (time.ctime(response.timestamp / 1000000), response.log))

class kwargs_append_action(argparse.Action):
    def __call__(self, parser, args, values, option_string=None):
        try:
            d = dict(map(lambda x: x.split('='),values))
        except ValueError as ex:
            raise argparse.ArgumentError(
                self, f"Could not parse argument \"{values}\" as k1=v1 k2=v2 ... format")

        setattr(args, self.dest, d)

def main():
    print("Velociraptor Hunt Scheduler")
    print("Code modified by: Keven Murphy")
    print("Version: ", version)
        
    parser = argparse.ArgumentParser(
        description="Hunt Scheduling.",
        epilog='Example: hunt_scheduler.py  --config api_client.yaml --csv hunts.csv'
        )

    parser.add_argument('--config', type=str,
                        help='Path to the api_client config. You can generate such '
                        'a file with "velociraptor config api_client" '
                        'See https://github.com/Velocidex/pyvelociraptor/blob/master/README.txt for details'                        
                        )

    parser.add_argument('--csv', type=str,
                        help='CSV file containing mass triage hunts and seetings '
                        'CSV needs to have the following header: artifact,time,pause,cpulimit')
    
    
    parser.add_argument('--ocsv',  action='store_true', required=False,
                        help='Output as CSV ')   
    
    parser.add_argument('--ojson',  action='store_true', required=False,
                        help='Output as JSON ')     
     

    parser.add_argument("--env", dest="env",
                        nargs='+',
                        default={},
                        required=False,
                        action=kwargs_append_action,
                        metavar="KEY=VALUE",
                        help="Add query environment values in the form of Key=Value.")

    #parser.add_argument('query', type=str, help='The query to run.')

    args = parser.parse_args()
    
    config = pyvelociraptor.LoadConfigFile(args.config)
    
    with open(args.csv) as csvfile:
        reader = csv.DictReader(csvfile)

        # making a list from the keys of the dict
        #colheader = list(dict_from_csv.keys())
        colheader = list(reader.fieldnames)
        #if 'cpu_limit' not in colheader:
        #    colheader
 
        # displaying the list of column names
        print("Column Headers from CSV File : ", reader.fieldnames)
  
   
        for row in reader:
           #print(list(row.keys()))            
           #headquery = ''
           if  'cpu_limit' not in row:
                   row['cpu_limit'] = '100'
           
           
           #for header in colheader:
           #     headquery = headquery + header + '=' + row[header]
                   
                   
           args.query = 'SELECT hunt(description=\"' + row['artifact'] + '\", artifacts=\'' + row['artifact'] + '\',  timeout=' + row['time'] + ', pause='+row['pause']+', cpu_limit=' + row['cpu_limit'] + ') FROM scope()'
           print('Running Hunt: ' + args.query)
           run(config, args.query, args.env, args.ocsv, args.ojson)

if __name__ == '__main__':
    main()
