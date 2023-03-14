#!/usr/bin/env python3
#
# Search Shodan and print summary information for the query.
#
# Author: akshay.nehate@n4l.co.nz

import shodan
import sys

# Configuration
API_KEY = ''

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

    print('Shodan Search Results')
    print('Query: %s' % query)
    print('Total Results: %s\n' % results['total'])

    # Print information about open ports and vulnerabilities
    for result in results['matches']:
        ip = result['ip_str']
        port = result['port']
        print('IP: %s' % ip)
        print('Port: %s' % port)

        if 'vulns' in result:
            vulnerabilities = result['vulns']
            print('Vulnerabilities: %s' % ', '.join(vulnerabilities))

        # Print an empty line between summary info
        print('')

except Exception as e:
    print('Error: %s' % e)
    sys.exit(1)
