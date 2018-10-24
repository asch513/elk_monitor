#!/usr/bin/env python3

import argparse
import os
import sys
import time
import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ELKMonitor(object):
    def __init__(self,index,user,password,url):
        self.index = index
        self.user = user
        self.password = password
        self.url = url
        self.search_url = "https://{}:{}@{}/{}/_search".format(self.user,self.password,self.url,self.index)
        self.count_url = "https://{}:{}@{}/{}/_count".format(self.user,self.password,self.url,self.index)

    def get_time_spec_json(self,earliest):
        # get upper limit of time range filter for query
        latest = "now"
        # get lower limit of time range filter for query
        earliest = "{}{}".format(latest, earliest)

        time_spec = { "range": { "@timestamp": { "gt": earliest, "lte": latest } } }

        return time_spec

    def getCountString(self,earliest,field,value):
        time_spec = self.get_time_spec_json(earliest)
        search_json = {
            'query': {
                'bool': {
                    'filter': [
                    {
                        "term": { field : value }
                    },
                    time_spec
                    ]
                }
            }
        }
        return search_json

    def checkFieldsExistsSearch(self,earliest,fields,query):
        time_spec = self.get_time_spec_json(earliest)
        fields_not_found = []
        for field in fields.split(","):
            search_json = {
                'query': {
                    'bool': {
                        'filter': [
                        {
                            'exists': {
                                'field': field
                            }
                        },
                        time_spec
                        ]
                    }
                }
            }
            search_json['size'] = 1 #as long as we see at leave 1, we are ok
            if query:
                q = { 'query_string' : { 'query': query } }
                search_json['query']['bool']['filter'].append(q)
            results = self.perform_query(search_json)
            if len(results['hits']['hits']) <  1:
                fields_not_found.append(field) 

        return fields_not_found

    def getDistinctFieldValueCount(self,earliest,field,query):
        search_json = self.getSearchString(earliest,field,query)
        search_results = self.perform_query(search_json)
        unique_field_values = self.getUniqueAggregationResults(search_results)
        return len(unique_field_values)-1
            

    def getSearchString(self,earliest,field,search,size=50000):
        time_spec = self.get_time_spec_json(earliest)
        
        search_json = {
            "_source": [field],
            "size": 0,
            "aggs" : {
                "time_filter" : {
                    "filter": time_spec
                     ,
                     "aggs": {
                         "unique_field": {
                             "terms": {
                                 "field": field,
                                 "size": size
                              }
                          }
                      }
                 }
            }
        }

        #if a filter search is defined in the ini file`
        if search:
            search_json["query"] = {
                    "bool":
                        {"filter":[
                            {"query_string":
                                {"query": search}
                            }
                        ]
                        }
                    }
            


        #print("search_json: {}".format(json.dumps(search_json)))
        return search_json

    def getLastSeenData(self,field,value):
        #to find the last time a value was seen seems to be inexpensive and doesn't require a timerange for efficiency
        search_json = { "size": 1,
                        "sort": [
                        {
                          "@event_timestamp": {
                            "order": "desc"
                          }
                        }
                        ], 
                        "query": 
                         { "term": 
                           {
                             field: {
                               "value": value
                             }
                           }
                         }
                      }
        results = self.perform_query(search_json)
        if len(results['hits']['hits']) > 0:
            return results['hits']['hits'][0]['_source']
        return None

    def perform_count(self,search_json):
        #print("count search: {}".format(json.dumps(search_json)))
        headers = {'Content-type':'application/json'}
        search_result = requests.get(self.count_url,data=json.dumps(search_json),headers=headers,verify=False)
        if search_result.status_code != 200:
            print("search failed {0}".format(search_result.text))
            sys.exit(3)
        #print("result messages: count:{} - _shards:{}".format(search_result.json()['count'],search_result.json()['_shards']))
        return search_result.json()

    def perform_query(self,search_json):
        print("json search: {}".format(json.dumps(search_json)))
        headers = {'Content-type':'application/json'}
        search_result = requests.get(self.search_url,data=json.dumps(search_json),headers=headers,verify=False)
        if search_result.status_code != 200:
            print("search failed {0}".format(search_result.text))
            sys.exit(3)
        #print("result messages: timed_out:{} - took:{} - _shards:{} - _clusters:{}".format(search_result.json()['timed_out'],search_result.json()['took'],search_result.json()['_shards'],search_result.json()['_clusters']))
        return search_result.json()

    """ json resultset schema
      "aggregations": {
        "time_period": {
          "meta": {},
          "doc_count": 8846,
          "unique_hostname": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [
              {
                "key": "nirvvdc201",
                "doc_count": 2053
              },
              {
                "key": "nexoha401",
                "doc_count": 352
              },
              ...
    """

        
    def getUniqueAggregationResults(self,search_results):
        l = []
        #print("Search Results in Aggregation Results: {}".format(search_results))
        if 'aggregations' not in search_results.keys():
            return l
        for item in search_results['aggregations']['time_filter']['unique_field']['buckets']:
            l.append(item['key']) 
        return l

    def getCount(self,earliest,field,value):
        search_json = self.getCountString(earliest,field,value)
        search_results = self.perform_count(search_json)
        return search_results['count']
        

    def getMissingFieldValues(self,earliest,field,expected_values,query):
        if type(expected_values) is str:
            expected_values = expected_values.split(",")
        search_json = self.getSearchString(earliest,field,query)
        search_results = self.perform_query(search_json)
        unique_field_values = self.getUniqueAggregationResults(search_results)
        missing = []
        for item in expected_values:
            if item not in unique_field_values:
                missing.append(item)
        return missing

    def getUniqueFieldValues(self,earliest,field,query):
        search_json = self.getSearchString(earliest,field,query)
        search_results = self.perform_query(search_json)
        return self.getUniqueAggregationResults(search_results)

    def checkCount(self,count,index,field,item,wlt,wgt,clt,cgt):
        monitor_results = []
        #print("Count is {} - {} - {}".format(field,item,count))
        print("index:{}, field:{}, item:{}, count:{}, wlt:{}, wgt:{}, clt:{}, cgt:{}".format(index,field,item,count,wlt,wgt,clt,cgt))
        if wlt:
            if count < int(wlt):
                monitor_results.append("WARNING: Index {}, Count {}, Expected Greater Than {}, Field {}, Value {}".format(index,count,wlt,field,item))
        if wgt:
            if count > int(wgt):
                monitor_results.append("WARNING: Index {}, Count {}, Expected Less Than {}, Field {}, Value {}".format(index,count,wgt,field,item))
        if clt:
            if count < int(clt):
                monitor_results.append("CRITICAL: Index {}, Count {}, Expected Greater Than {}, Field {}, Value {}".format(index,count,clt,field,item))
        if cgt:
            if count > int(cgt):
                monitor_results.append("CRITICAL: Index {}, Count {}, Expected Less Than {}, Field {}, Value {}".format(index,count,cgt,field,item))
        return monitor_results

        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', '--name', action='store', dest='name',
        required=True, default=None,
        help="Name of the Monitor")

    parser.add_argument('-d', '--description', action='store', dest='description',
        required=True, default=None,
        help="Description of the Monitor")

    parser.add_argument('-i', '--index', action='store', dest='index',
        required=True, default=None,
        help="Index in Elaticsearch to query")

    parser.add_argument('-l', '--url', action='store', dest='url',
        required=True, default=None,
        help="url of elasticsearch including port (search.local:9200)")

    parser.add_argument('-u', '--user', action='store', dest='user',
        required=True, default=None,
        help="User to use for elasticsearch connection.")

    parser.add_argument('-e', '--earliest', action='store', dest='earliest',
        required=False, default=None,
        help="Earliest time to search")

    parser.add_argument('-p', '--password', action='store', dest='password',
        required=True, default=None,
        help="Password to use for elasticsearch connection.")

    parser.add_argument('-q', '--query', action='store', dest='query',
        required=False, default=None,
        help="Lucene filter query to issue to elasticsearch (commonly used to whitelist items or be more specific within the index")

    parser.add_argument('-f', '--field', action='store', dest='field',
        required=False, default=None,
        help="Query to issue to elasticsearch (commonly used to whitelist items or be more specific within the index")

    parser.add_argument('-v', '--values', action='store', dest='values',
        required=False, default=None,
        help="Expected Values for unique values from field specified")

    parser.add_argument('-m', '--missing', action='store', dest='missing',
        required=False, default=None,
        help="Instead of a list of items that should be found, query the last X time period to get a list of items that should be found (default:-7d)")

    parser.add_argument('-w', '--warning-less-than', action='store', dest='warning_less_than',
        required=False, default=None,
        help="Issue WARNING if the query returns results less than this.")

    parser.add_argument('-W', '--warning-greater-than', action='store', dest='warning_greater_than',
        required=False, default=None,
        help="Issue WARNING if the query returns results more than this.")

    parser.add_argument('-c', '--critical-less-than', action='store', dest='critical_less_than',
        required=False, default=None,
        help="Issue CRITICAL if the query returns results less than this.")

    parser.add_argument('-C', '--critical-greater-than', action='store', dest='critical_greater_than',
        required=False, default=None,
        help="Issue CRITICAL if the query returns results greater than this.")

    parser.add_argument('-E', '--exist-fields', action='store', dest='exist_fields',
        required=False, default=None,
        help="comma separated list of field names we expect to witness with the search, alert if not found")
    args = parser.parse_args()

    if args.earliest and not args.earliest.startswith('-'):
        args.earliest = '-{}'.format(args.earliest)
    if args.missing and not args.missing.startswith('-'):
        args.missing = '-{}'.format(args.missing)

    if not args.warning_less_than and not args.warning_greater_than and not args.critical_less_than and not args.critical_greater_than and not args.values and not args.missing and not args.exist_fields:
        print("UNKNOWN: You must use at least one of: -w -W -c -C -v -m -E.")
        sys.exit(3)

    if (args.values and not args.field) or (args.missing and not args.field):
        print("UNKNOWN: if -v or -m is used, -f is required")
        sys.exit(3)

    # remove proxy if it's set
    if 'http_proxy' in os.environ:
        del os.environ['http_proxy']
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']

    monitor_results = []
    monitor = ELKMonitor(args.index,args.user,args.password,args.url)

    count = None
    ######################################################################
    # if a field is sent but not values and not looking for missing items
    # but, also want to check > <
    ######################################################################
    if args.field and not args.values and not args.missing and (args.warning_less_than or args.warning_greater_than or args.critical_less_than or args.critical_greater_than):
        #just get a distinct count of the field (and query) and check against less than/greater than items
        count = monitor.getDistinctFieldValueCount(args.earliest,args.field,args.query)
        print("Count of {} over {} for {} with query {}".format(count,args.earliest,args.field,args.query))
        monitor_results.extend(monitor.checkCount(count,args.index,args.field,args.field,args.warning_less_than,args.warning_greater_than,args.critical_less_than,args.critical_greater_than))
        
    if args.exist_fields:
        if not args.earliest:
            print("-e requires earliest time to be provided")
            sys.exit(3)
        print("Expected Field Names: {}".format(args.exist_fields))
        fields_not_found = monitor.checkFieldsExistsSearch(args.earliest,args.exist_fields,args.query)
        if fields_not_found:
            monitor_results.append("CRITICAL: Index {}, Item Not in List of Known Names {}".format(args.index,fields_not_found))

    values = []
    if args.values:
        values = args.values.split(',')
        print("Expected Items: {} - {}".format(args.field,values))

    found_values = []
    ######################################################################
    # if this is set, we search over the past X time period to fine unique 
    # values for the field provided to add to the list of items that should exist
    ######################################################################
    if args.missing:
        found_values = monitor.getUniqueFieldValues(args.missing,args.field,args.query)
        print("Found Items: {} - {}".format(args.field,found_values))

    # add found items to values list
    if args.missing and args.values:
        #are there new systems we don't know about and should? If we know about them and don't want this to match we need to add them to the whitelist
        for item in found_values:
            if item not in values:
                monitor_results.append("WARNING: Index {}, New Item Not in List of Known Values {} {}".format(args.index,args.field,item))
                # make sure we have all values
                values.append(item)

    # which items are missing from our existing list?
    missing = []
    if args.values and args.field and args.earliest:
        missing = monitor.getMissingFieldValues(args.earliest,args.field,args.values,args.query)

    # for each value either passed in or found via missing
    for item in values:
        #if item is missing, critical alert
        if item in missing:
            lastseen = monitor.getLastSeenData(args.field,item)
            if not lastseen: lastseen = "NEVER"
            monitor_results.append("CRITICAL: Index {}, Missing {} {}, LastSeen {}".format(args.index,args.field,item,lastseen))
        #if item is found, check volume levels
        elif args.warning_less_than or args.warning_greater_than or args.critical_less_than or args.critical_greater_than:
            #if we have already set the count from previous logic, don't get the count for this again
            if not count:
                count = monitor.getCount(args.earliest,args.field,item)
            monitor_results.extend(monitor.checkCount(count,args.index,args.field,item,args.warning_less_than,args.warning_greater_than,args.critical_less_than,args.critical_greater_than))
        #reset count if we are looping
        count = None

    #output the right criticality and exit - check most critical first
    criticality = ''.join(monitor_results) 
    if "CRITICAL:" in criticality:
        print("Alert: {}, Description: {}".format(args.name,args.description))
        print("{}".format(monitor_results))
        sys.exit(2)

    if "WARNING:" in criticality:
        print("Alert: {}, Description: {}".format(args.name,args.description))
        print("{}".format(monitor_results))
        sys.exit(1)
    
     
    print("OK: Name:{}, Description:{} - all checks passed.".format(args.name,args.description))
    sys.exit(0)
