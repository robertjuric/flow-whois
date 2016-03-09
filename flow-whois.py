import csv
from ipwhois import IPWhois
from pprint import pprint
import re


#Regex for skipping networks
privatepattern = re.compile("(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
linklocalpattern = re.compile("(^169\.254\.)")
specialusepattern = re.compile("(^2[4-5][0-9]\.)")
lacnicpattern = re.compile("(^191\.)")

#get fieldnames from column headers
f = open('test.csv', 'rb')
names = csv.reader(f).next()

#would like to add command line args for CSV filename
new_rows = []
with open ('test.csv', 'rb') as f:
	reader = csv.DictReader(f)
	for row in reader:
		new_row = row
		#specify column which has the IP to perform WHOIS Lookup
		lookup = row['SRC_ADDR_ID_IP']
		if privatepattern.match(lookup):
			print "%s is private address(RFC1918), skipping" % lookup 
			new_row['SRC_ADDR_ID_IP'] = lookup
		elif lookup == '0.0.0.0':
			print "%s is This Network(RFC1122), skipping" % lookup
			new_row['SRC_ADDR_ID_IP'] = lookup
		elif linklocalpattern.match(lookup):
			print "%s is link-local address(RFC3927), skipping" % lookup 
			new_row['SRC_ADDR_ID_IP'] = lookup
		elif specialusepattern.match(lookup):
			print "%s is special use, skiping" % lookup
			new_row['SRC_ADDR_ID_IP'] = lookup
		elif lacnicpattern.match(lookup):
			print "%s is LACNIC, skiping" % lookup
			new_row['SRC_ADDR_ID_IP'] = lookup
		else:
			print "%s is public address, looking up" % lookup
			#begin whois function
			obj = IPWhois(lookup)
			results = obj.lookup()
			domain = results['nets'][0]['name']
			#end whois function
			print "WHOIS Name: %s" % domain
			if domain is None:
				print "Blank domain, skipping"
				new_row['SRC_ADDR_ID_IP'] = lookup
			else:
				qchanges = { lookup : domain }
				newentry = lookup.replace(lookup, domain)
				print "new entry is %s" % newentry
				new_row['SRC_ADDR_ID_IP'] = newentry
		new_rows.append(new_row)
		
with open('modified.csv', 'wb') as f:
	fieldnames = ['SRC_ADDR_ID_IP']
	writer = csv.DictWriter(f, fieldnames=names)
	writer.writeheader()
	writer.writerows(new_rows)
