import shodan
import sys
SHODAN_API_KEY = "mv56tYo2TrU7j0d3za3qykdu5OuW4sox"
api = shodan.Shodan(SHODAN_API_KEY)
try:

	results = api.search(sys.argv[1:])
	for result in results['matches']:
		print '%s' % result['ip_str']

except shodan.APIError, e:
	print 'Error: %s' % e
