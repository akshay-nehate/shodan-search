#!/usr/bin/env python3
#
# Search Shodan and print summary information for the query.
#
# Author: akshay.nehate@n4l.co.nz

import shodan
import sys
import csv

# Configuration
#API_KEY = 'YOUR API KEY'
# Configuration


# Input validation
if len(sys.argv) == 1:
    print('Usage: %s <search query>' % sys.argv[0])
    sys.exit(1)

try:
    # Setup the api
    api = shodan.Shodan(API_KEY)

    # Generate a query string out of the command-line arguments
    query = ' '.join(sys.argv[1:])

    # Use the search() method to get results for the query
    results = api.search(query)

    # Write the results to a CSV file
    with open('results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write header row to CSV file
        writer.writerow(['IP', 'Port', 'Vulnerabilities'])

        # Write results to CSV file
        for result in results['matches']:
            ip = result['ip_str']
            port = result['port']

            if 'vulns' in result:
                vulnerabilities = ', '.join(result['vulns'])
            else:
                vulnerabilities = ''

            writer.writerow([ip, port, vulnerabilities])

except Exception as e:
    print('Error: %s' % e)
    sys.exit(1)
