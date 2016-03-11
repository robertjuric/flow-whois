import re
import sys

import pandas as pd

from ipwhois import IPWhois


# Regex for skipping networks
privatepattern = re.compile(
    "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)")
linklocalpattern = re.compile("(^169\.254\.)")
specialusepattern = re.compile("(^2[4-5][0-9]\.)")
lacnicpattern = re.compile("(^191\.)")
multicastpattern = re.compile("(^224\.)|(^239\.255\.255\.)")

pattern_list = [privatepattern, linklocalpattern, specialusepattern,
                lacnicpattern, multicastpattern]
local = '0.0.0.0'
# Function for getting WHOIS domen


def check_addr_type(addr, addr_dict):
    if addr != local and not any([pattern.match(addr) for pattern in pattern_list]):
        obj = IPWhois(addr)
        results = obj.lookup()
        domain = results['nets'][0]['name']
        if domain is not None:
            addr_dict[addr] = domain


def analyze_addr(main_df, col_to_process, whois_col_name):
    addr_dict = {}
    for el in main_df[col_to_process].unique():
        check_addr_type(el, addr_dict)
    # Converting python dict into DataFrame
    addr_df = pd.DataFrame(addr_dict.items(), columns=[col_to_process,
                                                       whois_col_name])
    # Merging two DataFrames based on left DF
    result_df = pd.merge(main_df, addr_df, on=[col_to_process], how='left')
    # Filling all NaN values in WHOIS column with the same values in
    # SRC_ADDR_ID_IP column
    result_df[whois_col_name] = result_df[
        whois_col_name].fillna(result_df[col_to_process])
    return result_df


def main(argv):
    if len(argv) > 0:
        inputfile = argv[0]
    else:
        print 'usage: flow-whois.py <inputfile>'
        sys.exit()

    outputfile = 'result.csv'
    src_addr_col = 'SRC_ADDR_ID_IP'
    dst_addr_col = 'DST_ADDR_ID_IP'
    whois_src_col_name = 'WHOIS_src'
    whois_dst_col_name = 'WHOIS_dst'
    to_analyze = [(src_addr_col, whois_src_col_name),
                  (dst_addr_col, whois_dst_col_name)]

    # Reading csv file into DataFrame
    main_df = pd.read_csv(inputfile)
    for addr_col, whois_name in to_analyze:
        main_df = analyze_addr(main_df, addr_col, whois_name)

    # Writing result DataFrame in csv file.
    main_df.to_csv(outputfile, columns=['APP_NAME', 'APP_ID',
                                        'original_source', src_addr_col,
                                        whois_src_col_name, 'SRC_hostname',
                                        'original_dest', dst_addr_col,
                                        whois_dst_col_name, 'DST_hostname',
                                        'LATEST_COLLECTION_TIME',
                                        'total_conv_size'])

if __name__ == '__main__':
    main(sys.argv[1:])
