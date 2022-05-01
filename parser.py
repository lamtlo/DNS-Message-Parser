from collections import OrderedDict

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
opcode_map = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE", 6: "DNS STATEFUL OPERATIONS"}

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
RCODE_map = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4:"NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 11: "DSOTYPENI", 16: "BADSIG", 17: "BADKEY", 18: "BADTIME", 19: "BADMODE", 20: "BADNAME", 21: "BADALG", 22: "BADTRUNC", 23: "BADCOOKIE"}

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
CLASS_map = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}    

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
TYPE_map = {1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG", 9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN", 21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX", 27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC", 33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6", 39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP", 56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF", 100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC", 104: "NID", 105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ANY", 256: "URI", 257: "CAA", 258: "AVC", 259: "DOA", 260: "AMTRELAY", 32768: "TA", 32769: "DLV"}
  
records = OrderedDict()
i = 24
curr = input()

def remove_offset(num: int) -> int:
    return num & (2**14 - 1)

def parse_RDATA(RDLENGTH: int, ATYPE: str) -> str:
    global i, records, curr

    if ATYPE == "A":
        RDATA = []
        for _ in range(RDLENGTH):
            ch = curr[i:i + 2]
            ch = str(int(ch, 16))
            RDATA.append(ch)
            i += 2
        RDATA = ".".join(RDATA)
    # Compress IPv6 address according to https://www.countryipblocks.net/ipv6_calculator.php
    elif ATYPE == "AAAA":
        RDATA = []
        for _ in range(RDLENGTH // 2):
            ch = curr[i:i + 4]
            ch = hex(int(ch, 16))[2:]
            RDATA.append(ch)
            i += 4
        curr_zero_count, max_zero_count = 0, 0
        shorthand_idx = -1
        for idx, val in enumerate(RDATA):
            if val == "0":
                curr_zero_count += 1
                if curr_zero_count > max_zero_count:
                    max_zero_count = curr_zero_count
                    shorthand_idx = idx - max_zero_count + 1
            else:
                curr_zero_count = 0
        if max_zero_count >= 2:
            RDATA = RDATA[:shorthand_idx] + [""] + RDATA[shorthand_idx + max_zero_count:]
        RDATA = ":".join(RDATA)
    elif ATYPE == "CNAME":
        RDATA = ""
        idx = 0
        byte_loc = i // 2
        records[byte_loc] = ""    
        while idx < RDLENGTH:
            label_char_count = int(curr[i:i+2], 16)
            if label_char_count > RDLENGTH - idx - 1:
                byte_loc_to_find = remove_offset(int(curr[i:i+4], 16))
                i += 4
                for key in records:
                    if byte_loc_to_find >= key:
                        label = records[key][byte_loc_to_find - key:]

                RDATA += label
                records[byte_loc] += label    

                idx += 4
            else:
                label = ""
                i += 2
                for _ in range(label_char_count):
                    ch = curr[i:i + 2]
                    ch = chr(int(ch, 16))
                    label += ch
                    i += 2
                label += "."
                
                RDATA += label
                records[byte_loc] += label    

                idx += label_char_count + 1
    return RDATA

def main():
    global i, records, curr
    
    # Parsing HEADER id and query parameters
    parsed_msg = ";; ->>HEADER<<-"

    ID = int(curr[:4], 16)
    query_param = int(curr[4:8], 16)
    opcode = (query_param >> 11) & 15
    RCODE = query_param & 15
    
    parsed_msg += " opcode: " + opcode_map[opcode]
    parsed_msg += ", status: " + RCODE_map[RCODE]
    parsed_msg += ", id: " + str(ID) 
    parsed_msg += "\n"
    
    # Parsing HEADER query count, answer count and authority count and additional count
    parsed_msg += ";; flags:"

    QR = query_param >> 15
    AA = (query_param >> 10) & 1
    TC = (query_param >> 9) & 1
    RD = (query_param >> 8) & 1
    RA = (query_param >> 7) & 1

    if QR:
        parsed_msg += " qr"
    if AA:
        parsed_msg += " aa"
    if TC:
        parsed_msg += " tc"
    if RD:
        parsed_msg += " rd"
    if RA:
        parsed_msg += " ra"
    
    QDCOUNT = int(curr[8:12], 16)
    ANCOUNT = int(curr[12:16], 16)
    NSCOUNT = int(curr[16:20], 16)    
    ARCOUNT = int(curr[20:24], 16)
    
    parsed_msg += "; QUERY: " + str(QDCOUNT)    
    parsed_msg += ", ANSWER: " + str(ANCOUNT)
    parsed_msg += ", AUTHORITY: " + str(NSCOUNT)
    parsed_msg += ", ADDITIONAL: " + str(ARCOUNT)
    parsed_msg += "\n\n"
    
    # Parsing question section
    parsed_msg += ";; QUESTION SECTION:\n"
    parsed_msg += ";"
    count = 0
    while count < QDCOUNT:
        byte_loc = i // 2
        records[byte_loc] = ""    
        while curr[i] != "0" or curr[i+1] != "0":    
            label_char_count = int(curr[i:i+2], 16)
            label = ""
            i += 2
            for _ in range(label_char_count):
                ch = curr[i:i + 2]
                ch = chr(int(ch, 16))
                label += ch
                i += 2
            label += "."
            parsed_msg += label
            records[byte_loc] += label        
        i += 2        
        QTYPE = int(curr[i:i+4], 16)
        i += 4
        QCLASS = int(curr[i:i+4], 16)
        i += 4
        
        
        parsed_msg += "\t\t"
        parsed_msg += CLASS_map[QCLASS]
        parsed_msg += "\t"
        parsed_msg += TYPE_map[QTYPE]

        count += 1
    parsed_msg += "\n\n"
        
    # Parsing answer section
    parsed_msg += ";; ANSWER SECTION:"
    count = 0
    while count < ANCOUNT:
        ANAME = int(curr[i:i+4], 16)
        ANAME = ANAME & (2**14 - 1)
        i += 4
        ATYPE = int(curr[i:i+4], 16)
        i += 4
        ACLASS = int(curr[i:i+4], 16)
        i += 8
        TTL = int(curr[i:i+4], 16)
        i += 4 
        RDLENGTH = int(curr[i:i+4], 16)
        i += 4
        
        RDATA = parse_RDATA(RDLENGTH, TYPE_map[ATYPE])
        
        parsed_msg += "\n" + records[ANAME]
        parsed_msg += "\t\t"
        parsed_msg += str(TTL)
        parsed_msg += "\t"
        parsed_msg += CLASS_map[ACLASS]          
        parsed_msg += "\t"
        parsed_msg += TYPE_map[ATYPE]
        parsed_msg += "\t"
        parsed_msg += RDATA

        count += 1
    
    print(parsed_msg)

if __name__ == "__main__":
    main()
