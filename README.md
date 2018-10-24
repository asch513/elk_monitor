# elk_monitor
There are plenty of tools available to monitor elasticsearch infrastructure, but knowing if certain logs are no longer being sent to elasticsearch is a problem I've seen across several companies. This script, initial created for integration with icinga, monitors if logs are not coming in from expected hosts, finds additional hosts that are sending logs, and when event ingestion volumes are out of spec.

```
usage: elk_monitor.py [-h] -n NAME -d DESCRIPTION -i INDEX -l URL -u USER
                      [-e EARLIEST] -p PASSWORD [-q QUERY] [-f FIELD]
                      [-v VALUES] [-m MISSING] [-w WARNING_LESS_THAN]
                      [-W WARNING_GREATER_THAN] [-c CRITICAL_LESS_THAN]
                      [-C CRITICAL_GREATER_THAN] [-E EXIST_FIELDS]

optional arguments:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Name of the Monitor
  -d DESCRIPTION, --description DESCRIPTION
                        Description of the Monitor
  -i INDEX, --index INDEX
                        Index in Elaticsearch to query
  -l URL, --url URL     url of elasticsearch including port
                        (search.local:9200)
  -u USER, --user USER  User to use for elasticsearch connection.
  -e EARLIEST, --earliest EARLIEST
                        Earliest time to search
  -p PASSWORD, --password PASSWORD
                        Password to use for elasticsearch connection.
  -q QUERY, --query QUERY
                        Lucene filter query to issue to elasticsearch
                        (commonly used to whitelist items or be more specific
                        within the index
  -f FIELD, --field FIELD
                        Query to issue to elasticsearch (commonly used to
                        whitelist items or be more specific within the index
  -v VALUES, --values VALUES
                        Expected Values for unique values from field specified
  -m MISSING, --missing MISSING
                        Instead of a list of items that should be found, query
                        the last X time period to get a list of items that
                        should be found (default:-7d)
  -w WARNING_LESS_THAN, --warning-less-than WARNING_LESS_THAN
                        Issue WARNING if the query returns results less than
                        this.
  -W WARNING_GREATER_THAN, --warning-greater-than WARNING_GREATER_THAN
                        Issue WARNING if the query returns results more than
                        this.
  -c CRITICAL_LESS_THAN, --critical-less-than CRITICAL_LESS_THAN
                        Issue CRITICAL if the query returns results less than
                        this.
  -C CRITICAL_GREATER_THAN, --critical-greater-than CRITICAL_GREATER_THAN
                        Issue CRITICAL if the query returns results greater
                        than this.
  -E EXIST_FIELDS, --exist-fields EXIST_FIELDS
                        comma separated list of field names we expect to
                        witness with the search, alert if not found
```

## Examples

Check for missing logs from a specific host, alert if host hasn't logged in the last hour, alert if the amount of events in the last hour are not within an upper and lower boundary.

- name of the alert: ``` -n 'CB - Log Issue' ```
- description of alert: ```-d 'Carbonblack Check For Missing Logs and Consumption Levels' ```
- user & password to elasticsearch: ``` -u 'icinga' -p 'passwordforicingauser' -i ```
- index to search: ``` -i '\*:carbonblack' ```
- elasticsearch url: ``` -l 'search.local:9200' ```
- search the past 1 hour: ``` --earliest='-1h' ```
- field to search: ``` -f 'host' ```
- expected values to find with the search: ``` -v cbmas.local.com ```
- warn if number of events more than expected: ``` -W '10000000' ```
- warn if number of events are less than expected: ``` -w '2500000' ```
- list of fields that should exist in elasticsearch: ``` -E 'method,mime_type,seen_bytes,src_ip,src_ip.ip,dst_ip,dst_ip.ip,type,status_code ```

      python3 elk_monitor.py -n 'CB - Log Issue' -d 'Carbonblack Check For Missing Logs and Consumption Levels' -u 'icinga' -p 'passwordforicingauser' -i '\*:carbonblack' -l 'search.local:9200' --earliest='-1h' -f 'host' -v 'cbmaster.local.com' -W '10000000' -w '2500000'

      python3 elk_monitor.py -n 'Bro - Field Name Issue' -d 'Bro Check For Expected Field Names' -u 'icinga' -p 'passwordforicingauser' -i 'bro' -l 'elasticsearch.local' --earliest='-6h' -E 'index,method,mime_type,seen_bytes,src_ip,src_ip.ip,dst_ip,dst_ip.ip,type,status_code,msg,note'
