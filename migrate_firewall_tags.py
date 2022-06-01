"""
src/DockerImageBuilder/build_dev.py
Script to handle building dev images of Meru data-plane applications.
"""

from argparse import ArgumentParser
from ipaddress import ip_address, IPv4Address
from ctypes import sizeof
from pathlib import Path
import re
import os
import sys
import json
from tracemalloc import start

def main():
    """
    The top-level function of the script that takes the args, builds the
    images and updates the Application files for orcasql-breadth.
    """
    options = process_arguments()
    os.system("az login")
    migrate_firewall_rules(options)
    migrate_resource_tags(options)
    print("Success")


def validIPAddress(IP: str) -> str:
    try:
        return "IPv4" if type(ip_address(IP)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"

def migrate_resource_tags(options):
    source_server_resource_id = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.DBforPostgreSQL/servers/{2}".format(options.get('srcsub'),options.get('srcrg'),options.get('srcpg'))
    single_server_tags = os.popen("az tag list --resource-id {}".format(source_server_resource_id)).read()
    single_server_tags = json.loads(single_server_tags).get('properties').get('tags')
    flex_server_resource_id = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.DBforPostgreSQL/flexibleServers/{2}".format(options.get('targetsub'),options.get('targetrg'),options.get('targetpg'))
    tag_str = ""
    for key in single_server_tags:
        tag_str+=key+'='+single_server_tags[key]+" "
    result = os.system("az tag update --operation Merge --resource-id {0} --tags {1}".format(flex_server_resource_id,tag_str))
    if result == 0:
        print("Successfully migrated resource tags")
        print("\n")
        print("\n")
        print("############################################################################")
        print("\n")
        print("IT WILL TAKE SOMETIME FOR RESOURCE TAGS TO REFLECT IN FLEX SERVER PORTAL....")
        print("\n")
        print("############################################################################")

    else:
        print("Error while igrating resource tags")


def migrate_firewall_rules(options):
    source_firewall_rules = os.popen("az postgres server firewall-rule list -g {0} -s {1} --subscription {2}".format(options.get('srcrg'),options.get('srcpg'),options.get('srcsub'))).read()
    ss_firewall_rules_list = json.loads(source_firewall_rules)
    flex_server_name = options.get('targetpg')
    flex_server_rg = options.get('targetrg')
    flex_server_sub = options.get('targetsub')
    for rule in ss_firewall_rules_list:
        rule_name = rule.get('name')
        startip = rule.get("startIpAddress")
        endip = rule.get("endIpAddress")
        if validIPAddress(startip) != "IPv4" and validIPAddress(endip) != "IPv4":
            print("IP address in the rules are not IPv4 addresses")
            break
        else:
            result = os.system("az postgres flexible-server firewall-rule create --subscription {0} -g {1} -n {2} --start-ip-address {3} --end-ip-address {4} -r {5}".format(
                flex_server_sub,flex_server_rg,flex_server_name,startip,endip,rule_name))
            if(result==0):
                print("Successfully migrated Firewall Rule {}".format(rule_name))
    print("####################################################################################################")
    print("\n")
    print("MIGRATING FIREWALL RULES DOES NOT MEAN YOUR NETWORK CONFIGURATION FOR SINGLE SERVER IS ALSO MIGRATED")
    print("\n")
    print("####################################################################################################")



def process_arguments():
    """
    Process the command line arguments to get the list of images to
    build and options.
    """
    parser = ArgumentParser()

    # Options
    parser.add_argument("-srcsub", "--source-subscription", 
                        dest='source_sub', required=True,
                        help="azure Subscription ID containing single server PG")

    parser.add_argument("-srcrg", "--source-resource-grp",
                        dest="source_resource_grp", required=True,
                        help="Resource group name of Single server PG")
    
    parser.add_argument("-srcpg", "--source-single-server",
                        dest="source_single_server", required=True,
                        help="Single Server PG name")

    parser.add_argument("-targetsub", "--target-subscription", required=True,
                        dest='target_sub',
                        help="Azure Subscription ID containing Flexible server PG")

    parser.add_argument("-targetrg", "--target-resource-grp",
                        dest="target_resource_grp", required=True,
                        help="Resource group name of Flexible server PG")
    
    parser.add_argument("-targetpg", "--target-flexible-server",
                        dest="target_flex_server", required=True,
                        help="Flexible Server PG name")

   
    args = parser.parse_args()

    options = {}

    options["srcsub"] = args.source_sub
    options["srcrg"] = args.source_resource_grp
    options["srcpg"] = args.source_single_server
    options["targetsub"] = args.target_sub
    options["targetrg"] = args.target_resource_grp
    options["targetpg"] = args.target_flex_server
    return options



if __name__ == "__main__":
    main()
