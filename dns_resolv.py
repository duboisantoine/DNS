"""Module for sending DNS queries and anlysing the received DNS responses"""

from typing import Dict
from my_dns import TYPE, CLASS, idcount


def send_query(query, dns_server):
    """Send a dns packet datagram on the network and return the response receive packet.

    This function uses a **network socket** to send a **dns_packetgram message** to a DNS server. The message carried by the dns_packetgram is a DNS query. The transport protocol used is UDP. It returns the DNS response and then closes the socket at the end of the execution.

    :param query: the packet of bytes that constitutes a complete request
    :param dns_server: IP address or FQDN of the server
    :type query: array of bytes
    :type dns_server: string

    :return: array of bytes representing the response

    """

    import socket

    UDP_PORT = 53

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(query, (dns_server, UDP_PORT))
        sock.settimeout(10)
        dns_packet, addr = sock.recvfrom(1024) # buffer size is 1024 bytes

    except:
        print("No response from serveur !")
        dns_packet=None

    finally:
        print("Connection closed !")
        sock.close()
    return dns_packet

def set_query(query_name, query_type): # à compléter
    """Uses the query and type parameters to form the byte packet representing the DNS query to be sent.
    
    * The first twelve bytes are the header of th DNS request
    * Next bytes represents the question. 
    
    .. Important:: 
        extract from the **RFC1035** (*3.1. Name space definition*)
        
        *Domain names in messages are expressed in terms of a sequence of labels. Each label is represented as a one byte length field followed by that number of bytes. Since every domain name ends with the null label of the root, a domain name is terminated by a length byte of zero. The high order two bits of every length byte must be zero, and the remaining six bits of the length field limit the label to 63 bytes or less.*


    :param query_name: FQDN or Domain Nale or IP Address to resolve
    :param query_type: Type of DNS resolution
    :type query_name: string
    :type query_type: string

    :return: array of bytes représenting de query.
    """
    global idcount
    idcount += 1

    #:composition of the DNS request header
    ID = idcount.to_bytes(2, 'big') # convert to 2 bytes in bigEndian représentation 
                                    # (the most significant byte is at the beginning of the byte array)
    FLAGS = b'\x01\x00'
    QDCOUNT = b'\x00\x01'
    ANCOUNT = b'\x00\x00'
    NSCOUNT = b'\x00\x00'
    ARCOUNT = b'\x00\x00'
    header = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    # Another method is to create the byte array directly
    # header = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'

    query = None

    #: separate each part from the query_name
    labels = query_name.split('.')

    
    if query_type == 'PTR':
        #if the query is of type PTR return the IP address then add "in-addr" and "arpa" to it
        for label in labels:
            try:
                int(label)
            except:
                print("ERROR : Illegal use of PTR request")
                print("You need to enter an IPV4 address")

        labels = labels[::-1]
        labels.append("in-addr")
        labels.append("arpa")

    for label in labels:
        # in each part take the length of the label then translate the label into bytes
        if query == None:
            query = bytes([len(bytes(label,'utf-8'))]) + bytes(label, 'utf-8')
        else:
            query += bytes([len(bytes(label,'utf-8'))]) + bytes(label, 'utf-8')
    
    #: end of domain label
    query += b'\x00'

    # Concatenation of header with the QNAME, QTYPE and QCLASS fields according 
    # RFC1035 specifications
    return header + query + TYPE.get(query_type) + CLASS.get('IN')

def get_header(dns_packet): # à compléter
    """
    function that creates a dictionary that allows to separate each part of the header: 
    id (2 bytes),
    flag ( 2 bytes :
     (QR: 1bit), (Opcode: 4bit), (AA: 1bit), (TC: 1bit), (RD: 1bit), (RA: 1bit), (Z: 3bit), (Rcode: 4bit)),
    qdcount ( 2 bytes),
    ancount (2 bytes), 
    nscount (2 bytes), 
    arcount (2 bytes) 
    and then return it.

    
    :param dns_packet: The  packet received to analysis
    :type dns_packet: array of bytes

    :return: dictionary of DNS header fields
    """

    #:variable that takes the flag in bytes and transforms it into bits in the list 
    flag=bin(int.from_bytes(dns_packet[2:4],"big"))
    #:allows to remove the first two not useful in the list
    flag=flag[2::]

    #initialization of the dictionary that will contain each value of the header 
    header={}
    
    header["ID"]=dns_packet[0:2]
    header["FLAG"]= {'QR': flag[0:1],
                    'Opcode': flag[1:5],
                    'AA': flag[5:6],
                    'TC': flag[6:7],
                    'RD': flag[7:8],
                    'RA': flag[8:9],
                    'Z':flag[9:12],
                    'RCODE': flag[12:16] }

    header["QDCOUNT"]=int.from_bytes(dns_packet[4:6],"big")
    header["ANCOUNT"]=int.from_bytes(dns_packet[6:8],"big")
    header["NSCOUNT"]=int.from_bytes(dns_packet[8:10],"big")
    header["ARCOUNT"]=int.from_bytes(dns_packet[10:12],"big")
    
    return header

def get_query(dns_packet): 
    """Extract the DNS QUERY from the **dns_packet** argument and return a dictionnary representing the different fields of the QUERY
    
    .. Important:: 
        extract from the **RFC1035** : *4.1 Format*

        All communications inside of the domain protocol are carried in a single
        format called a message.  The top level format of message is divided
        into 5 sections (some of which are empty in certain cases) shown below:

        +---------------------+------------------------------------+
        |        Header       |                                    |
        +---------------------+------------------------------------+
        |       Question      | the question for the name server   |
        +---------------------+------------------------------------+
        |        Answer       | RRs answering the question         |
        +---------------------+------------------------------------+
        |      Authority      | RRs pointing toward an authority   |
        +---------------------+------------------------------------+
        |      Additional     | RRs holding additional information |
        +---------------------+------------------------------------+

        The header section is always present.  The header includes fields that
        specify which of the remaining sections are present, and also specify
        whether the message is a query or a response, a standard query or some
        other opcode, etc.

        The names of the sections after the header are derived from their use in
        standard queries.  The question section contains fields that describe a
        question to a name server.  These fields are a query type (QTYPE), a
        query class (QCLASS), and a query domain name (QNAME).
        
        The last three sections have the same format: a possibly empty list of 
        concatenated resource records (RRs).  The answer section contains RRs 
        that answer the question; the authority section contains RRs that point
        toward an authoritative name server; the additional records section 
        contains RRs which relate to the query, but are not strictly answers 
        for the question.

    :param dns_packet: The  packet received to analysis
    :type dns_packet: array of bytes

    :return: dictionary of query fields.
    :rtype: Dict

    """
    idx_end = dns_packet.find(b'\x00',12)   # '... domain name is terminated by a length byte of zero ...
    query = dns_packet[12:idx_end]          # Isolate the bytes representing the question
     
    # Query traitment - extract Fully Qualified Domain Name recovery
    idx_start = 0                           # idx_start represent a length Label byte
    idx_end = int(query[idx_start]+1)       
    dns_query = query[idx_start+1:idx_end]  # extract bytes representing first label

    while idx_end < len(query):             # Loop to extract the other labels and build th FQDN
        idx_start = idx_end
        idx_end = idx_start + int(query[idx_start]+1)
        dns_query += b'.'+ query[idx_start+1:idx_end]

    # Query traitment - extract DNS query Type 
    query_type = dns_packet[idx_end + 12 + 1: idx_end + 12 + 3]      # extract bytes representing QTYPE field
    QTYPE = list(TYPE.keys())[list(TYPE.values()).index(query_type)] # get the DNS Type 

    # Query traitment - extract DNS query class 
    query_class = dns_packet[idx_end + 12 + 3: idx_end + 12 + 5]      # extract bytes representing QCLASS field
    QCLASS = list(CLASS.keys())[list(CLASS.values()).index(query_class)] # get the DNS Class

    return {'QNAME': dns_query.decode(), 'TYPE': QTYPE, 'CLASS':QCLASS, 'QLENGTH': idx_end + 5}

def get_rr_suffix(idx, dns_packet):
    """Extract the **domain name** or the **suffix** of a resource record from the ``dns_packet`` argument. It return a string representing the name of the current record or its *rdata*.
    
    .. Important::

        Extract from the **RFC1035** (*3.1. Name space definitions*)
        
        * Domain names in messages are expressed in terms of a sequence of labels. Each label is represented as a one byte length field followed by that number of bytes. Since every domain name ends with the null label of the root, a domain name is terminated by a length byte of zero. The high order two bits of every length byte must be zero, and the remaining six bits of the length field limit the label to 63 bytes or less.*::

            +--+--+--+--+--+--+--+--+
            | 0 0 |  LABEL LENGTH   |
            +--+--+--+--+--+--+--+--+

        * In order to reduce the size of messages, the domain system utilizes a compression scheme which eliminates the repetition of domain names in a message.  In this scheme, an entire domain name or a list of labels at the end of a domain name is replaced with a pointer to a prior occurance of the same name.

        The pointer takes the form of a two bytes sequence::

            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            | 1  1|                OFFSET                   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        The first two bits are ones.  This allows a pointer to be distinguished from a label, since the label must begin with two zero bits because labels are restricted to 63 bytes or less.  (The 10 and 01 combinations are reserved for future use.)  The OFFSET field specifies an offset from the start of the message (i.e., the first byte of the ID field in the domain header).  A zero offset specifies the first byte of the ID field, etc.

        The compression scheme allows a domain name in a message to be represented as either:

        * a sequence of labels ending in a zero byte
        * a pointer
        * a sequence of labels ending with a pointer

    :param dns_packet: The  packet received to parse
    :param idx: The position in packet byte array where the parsing should start
    :type packet: array of bytes
    :type idx: Integer
    :return: The domain name of the record.
    :rtype: String

    """

    rr_suffix = b''
    if dns_packet[idx] >= 0xc0:
        idx = int.from_bytes(dns_packet[idx:idx+2], 'big') & 0x3fff

    while 0 < int(dns_packet[idx]) < 0x40:
        if rr_suffix == b'':
            rr_suffix = dns_packet[idx+1:idx+int(dns_packet[idx]+1)]
        else:
            rr_suffix += b'.' + dns_packet[idx+1:idx+int(dns_packet[idx]+1)]
        idx += int(dns_packet[idx]) + 1

        # test if next bytes are labels or pointer 
        if dns_packet[idx] >= 0xc0:
            idx = int.from_bytes(dns_packet[idx:idx+2], 'big') & 0x3fff

    return rr_suffix.decode('utf-8')

def get_fields(dns_records):
    """
    function that makes a dictionary containing the values of the type, the class, the Time To Live 
    and the length. it returns a dictionary that for the type and the class contains the values found 
    in the dictionaries TYPE and CLASS and for the ttl and the length the values are integers


    :param dns_records: The  packet received to analysis
    :type dns_records: array of bytes

    :return: dictionary of type, class, Time To Live (ttl) and length
    """
    #:iniatilisation of the variable that contains the dns_records bytes packet
    records=dns_records[::]
    
    #initialization of the dictionary to store the different fields of dns_records
    fields={}

    #::initialization of the variables that will contain the values found in the dictionaries (str)
    find_type=""
    find_class=""
    for key, value in TYPE.items():
        
        #search for the type with the TYPE dictionary by looking for the right key corresponding to the value
        if value == records[0:2]:
            find_type=key
    for key, value in CLASS.items():
        #search for the class with the CLASS dictionary by looking for the right key corresponding to the value
        if value == records[2:4]:
            find_class=key
        
    #aggregation of the dictionary with each value that corresponds
    fields["rr_type"]=find_type
    fields["class"]=find_class
    fields["ttl"]=int.from_bytes(records[4:8],"big")
    fields["rr_length"]=int.from_bytes(records[8:10],"big")
    return fields
   

def get_rrs(dns_packet):
    """Extract the **Ressource Records** (*RRs*) from the ``dns_packet`` argument and return a dictionnary representing the different records. Each RR is a dictionary of DNS fields.
    
    .. Important:: 
    
        The answer, authority, and additional sections all share the same
        format: a variable number of resource records, where the number of
        records is specified in the corresponding count field in the header.
        Each resource record has the following format::

            0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      NAME                     |   Tomain name of this resource record
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TYPE                     |   2 bytes of the RR type codes
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     CLASS                     |   2 bytes of the RR class codes
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TTL                      |   32 bit unsigned integer, time interval (in seconds) that the resource record may be cached before it should be discarded
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                   RDLENGTH                    |   16 bit unsigned integer that specifies the length in bytes of the RDATA field
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
            |                     RDATA                     |   Variable length byte array that describe the resource, 
            |                                               |   The format varies according to the TYPE and CLASS of the resource record
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    :param dns_packet: The  packet received to analysis
    :type dns_packet: array of bytes
    :return: dictionary of query fields.
    :rtype: Dict

    """

    # Initiate the dictionary of RRs to return
    rrs = {"answers":{}, "authorities":{}, "additionals":{}}

    # Initialization local variables
    idx_next=0
    idx_start_name = 0
    idx_current = 0
    cursor = 0

    # Extract the header to get the number of ressource records in each section of the response : answer, authority and additional
    header = get_header(dns_packet)
    nb_records = header.get('ANCOUNT') + header.get('NSCOUNT') + header.get('ARCOUNT')

    # Extract the query to get the size of the query and deduct the start index of the RRS in the response byte array
    query = get_query(dns_packet)

    # Extract form the response a byte array of all the RRs 
    dns_records = dns_packet[query.get('QLENGTH') + 12:]        # Byte array of all the RRs from DSN response

    # Extract all fieads of each RRs of the response
    while nb_records > 0:
        rr_name = ''
        dict_record = {}
        idx_start_name = idx_current
   
        # Test if rr_name is a pointer to another position in the array (first byte value upper than '0xc0') or a length label
        if int(dns_records[idx_start_name]) >= 0xc0:
            # Get the pointer value from the 14 low order bits of the 2 bytes representing the position index of next label bytes
            cursor = int.from_bytes(dns_records[idx_start_name:idx_start_name+2], 'big') & 0x3fff 
            idx_current = idx_start_name + 2
            
        else:
            while 0 < int(dns_records[idx_start_name]) < 0x40:
                if rr_name == '':
                    rr_name = dns_records[idx_start_name+1:idx_start_name+int(dns_records[idx_next + idx_start_name]+1)].decode()
                else:
                    rr_name += '.' + dns_records[idx_start_name+1:idx_start_name+int(dns_records[idx_next + idx_start_name]+1)].decode()

                idx_start_name += int(dns_records[idx_start_name]) + 1

                # test if next byte is a pointer to another position in the array
                if dns_records[idx_start_name] >= 0xc0:
                    idx_current = idx_start_name + 2
                    cursor = int.from_bytes(dns_records[idx_start_name:idx_start_name+2], 'big') & 0x3fff
                    break
        if cursor != 0 :
            rr_name += get_rr_suffix(cursor, dns_packet)            
        else :
            idx_current = idx_start_name + 1

        dict_record["rr_name"] = rr_name

        # Query traitment - extract DNS Answer Resource Record  Type nb_RRs
        fields = get_fields(dns_records[idx_current:])

        idx_current += 10

        dict_record = {**dict_record, **fields}

        if fields.get("rr_type") == 'A':
            rdata = get_rdata_A(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'NS':
            rdata = get_rdata_NS(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'CNAME':
            rdata = get_rdata_CNAME(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'SOA':
            rdata = get_rdata_SOA(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'PTR':
            rdata = get_rdata_PTR(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'MX':
            rdata = get_rdata_MX(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        elif fields.get("rr_type") == 'AAAA':
            rdata = get_rdata_AAAA(idx_current+query.get('QLENGTH') + 12, dns_packet)
            idx_current += int(fields.get("rr_length"))
            dict_record = {**dict_record, **rdata}

        if nb_records > header.get('NSCOUNT') + header.get('ARCOUNT'):
            if rrs.get("answers").get(rr_name) == None:
                rrs.get("answers")[rr_name]=[]
            rrs.get("answers")[rr_name].append(dict_record)
        elif nb_records > header.get('ARCOUNT'):
            if rrs.get("authorities").get(rr_name) == None:
                rrs.get("authorities")[rr_name]=[]
            rrs.get("authorities")[rr_name].append(dict_record)
        elif nb_records > 0:
            if rrs.get("additionals").get(rr_name) == None:
                rrs.get("additionals")[rr_name]=[]
            rrs.get("additionals")[rr_name].append(dict_record)

        idx_start_name = idx_current + 10
        idx_next = idx_start_name
        nb_records -= 1
    return rrs

def get_rdata_name(cursor, dns_packet): 
    """
    Extract the domain name of the Ressource Record from the RR’s rdata field and return it in string format.
     it calls the get_rdata_suffix(cursor, dns_packet) to do this.

    :param cursor: The position in packet byte array where the parsing should start
    :param dns_packet: The  packet received to analysis
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: the domain name in DNS rdata ressource record.
    :return type: string
    """
    rr_suffix = b''
    if dns_packet[cursor] >= 0xc0:
        cursor = int.from_bytes(dns_packet[cursor:cursor+2], 'big') & 0x3fff

    while 0 < int(dns_packet[cursor]) < 0x40:
        if rr_suffix == b'':
            rr_suffix = dns_packet[cursor+1:cursor+int(dns_packet[cursor]+1)]
        else:
            rr_suffix += b'.' + dns_packet[cursor+1:cursor+int(dns_packet[cursor]+1)]
        cursor += int(dns_packet[cursor]) + 1

        # test if next bytes are labels or pointer 
        if dns_packet[cursor] >= 0xc0:
            cursor = int.from_bytes(dns_packet[cursor:cursor+2], 'big') & 0x3fff

    return rr_suffix.decode('utf-8')


def get_rdata_A(cursor, dns_packet): 
    """
    function that allows to form the IPv4 address with the bytes of the response and to return it 
    in a dictionary


    :param cursor: the place in the data where you need to be to analyze the answer
    :param dns_packet: The  packet received to analysis
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: dictionary of DNS header fields
    :return type: Dict
    """

    #initialization of the dictionary which will contain the address
    dict_address={}

    #delimitation of the bytes to be translated
    data_bytes = dns_packet[cursor :cursor + 5]

    #variable where we get each part of the IP address to assemble it
    rdata_A = str(int(data_bytes[0])) + "." + str(int(data_bytes[1])) + "." + str(int(data_bytes[2])) + "." + str(int(data_bytes[3]))    
    dict_address["address_IPv4"] = rdata_A
    return dict_address

def get_rdata_NS(cursor, dns_packet): 
    """
    Extract the domain name of the Ressource Record from the RR’s rdata field in NS 
    response and return it.

    :param cursor: the place in the data where you need to be to analyze the answer
    :param dns_packet: The packet received to parse
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: Dictionary with a single key ‘Name server’ whose value is the domain name 
    string of rdata ressource record
    :return type: Dict
    """
    #initialization of the dictionary which will contain the name server.
    server_name={}

    #call of the function rdata_name in the variable rdata_ns
    rdata_ns={get_rdata_name(cursor,dns_packet)}

    #add the variable rdata_ns to the dictionary
    server_name["Name Server"]= rdata_ns
    return server_name

def get_rdata_CNAME(cursor, dns_packet):
    """
    :param cursor: the place in the data where you need to be to analyze the answer
    :param dns_packet: The packet received to parse
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: A Dictionary with a single key ‘Canonical name’ whose value is the domain name string 
    of rdata ressource record.
    :return type: Dict
    """
    #initialization of the dictionary which will contain the canonical name
    canonical_name={}

    #call of the function rdata_name in the variable rdata_cname
    rdata_cname={get_rdata_name(cursor,dns_packet)}

    #add the variable rdata_cname to the dictionary
    canonical_name["Canonical name"]= rdata_cname
    return canonical_name


def get_rdata_PTR(cursor, dns_packet):
    """
    Extract the domain name of the Ressource Record from the RR’s rdata field in PTR response and return it.

    :param cursor: The position in packet byte array where the parsing should start
    :param dns_packet: The packet received to parse
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: Dictionary with a single key ‘Name’ whose value is the domain name string 
    of rdata ressource record
    :return type: Dict
    """

    #initialization of the dictionary which will contain the Name
    server_name={}

    #call of the function rdata_name in the variable rdata_ptr
    rdata_ptr={get_rdata_name(cursor,dns_packet)}
    
    #add the variable rdata_ptr to the dictionary
    server_name["Name"]= rdata_ptr
    return server_name
    
 

def get_rdata_MX(cursor, dns_packet): 
    """
    Extract the domain name and the priotrity of the Ressource Record from the RR’s rdata 
    field of MX response and return it.

    :param cursor: The position in packet byte array where the parsing should start
    :param dns_packet: The packet received to parse
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: A Dictionary with a two keys, ‘Mail exchanger’ whose value is the domain
     name string of rdata ressource record and ‘Preference’ whose value is an integer 
     for the preference given to this RR at the same owner
    :return type: Dict
    """
    #initialization of the dictionary which will contain the mail exchanger and the preference
    dict_mx={}

    #call of the function rdata_name in the variable rdata_mail
    rdata_mail={get_rdata_name(cursor+2,dns_packet)}

    #recover the first two bytes that we convert into integer 
    rdata_pref=int.from_bytes(dns_packet[cursor:cursor+2],"big")

    #add the variable rdata_mail and rdata_pref to the dictionary
    dict_mx["Mail exchanger"]= rdata_mail
    dict_mx["Preference"]= rdata_pref

    return dict_mx


def get_rdata_SOA(cursor, dns_packet):
    """Extract the SOA fields of the **Ressource Record** from the rr's rdata field and return a dictionary. A SOA marks the start of a zone of authority.


    .. Important::

        SOA records cause no additional section processing. The fields below describe the Name Server.::

            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            /                     MNAME                     /   Name server that was the original original or 
            /                                               /   primary source of data for this zone
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            /                     RNAME                     /   The mailbox of the person responsible for this zone
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    SERIAL                     |   The unsigned 32 bit version number of the   
            |                                               |   original copy of the zone.
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    REFRESH                    |   A 32 bit time interval before the zone 
            |                                               |   should be refreshed
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     RETRY                     |   A 32 bit time interval that should elapse 
            |                                               |   before a failed refresh should be retried.
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    EXPIRE                     |   A 32 bit time value for the upper limit on the time  .
            |                                               |   interval before the zone is no longer authoritative
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                    MINIMUM                    |   The unsigned 32 bit minimum TTL field that should be
            |                                               |   exported with any RR from this zone.
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    :param dns_packet: The  packet received to parse
    :param cursor: The  position in packet byte array where the parsing should start
    :type dns_packet: Array of bytes
    :type cursor: Integer
    :return: A Dictionary of SOA fields representing the name server in rdata ressource record.
    :rtype: Dict

    """

    idx = 0
    rdata_bytes = dns_packet[cursor:]   

    # Query traitment - extract Responsive authority's server name
    rdata_server = ''
    # Loop to get the first labels of server name
    while 0 < int(rdata_bytes[idx]) < 0x40:
        if rdata_server == '':
            rdata_server = rdata_bytes[idx + 1:int(rdata_bytes[idx]+1)].decode()
        else:
            rdata_server += '.' + rdata_bytes[idx + 1:int(rdata_bytes[idx]+1)].decode()
        
        idx += int(rdata_bytes[idx] + 1)
    
        # test if next byte is a pointer to another position in the array 
        if rdata_bytes[idx] >= 0xc0:
            cursor = int.from_bytes(rdata_bytes[idx:idx+2], 'big') & 0x3fff
            idx += 2
            break
    # Get the suffix of server name
    rdata_server += '.' + get_rr_suffix(cursor, dns_packet) 

    # Query traitment - extract Responsive authority's mail name
    rdata_mail = ''
    # Loop to get the first labels of server name
    while 0 < int(rdata_bytes[idx]) < 0x40:
        if rdata_mail == '':
            rdata_mail = rdata_bytes[idx + 1: idx + int(rdata_bytes[idx]) + 1].decode()
        else:
            rdata_mail += '.' + rdata_bytes[idx + 1 : idx + int(rdata_bytes[idx]) + 1].decode()

        idx += int(rdata_bytes[idx] + 1)

        # test if next byte is a pointer to another position in the array
        if rdata_bytes[idx] >= 0xc0:
            cursor = int.from_bytes(rdata_bytes[idx:idx+2], 'big') & 0x3fff
            idx += 2
            break
    # Get the suffix of mail name
    rdata_mail += '.' + get_rr_suffix(cursor, dns_packet)

    # Query traitment - extract Serial number
    rr_serial_bytes = rdata_bytes[idx: idx + 4]  
    rr_serial = int.from_bytes(rr_serial_bytes, 'big')

    # Query traitment - extract Refresh interval
    rr_refresh_bytes = rdata_bytes[idx + 4: idx + 8]
    rr_refresh = int.from_bytes(rr_refresh_bytes, 'big')

    # Query traitment - extract Retry interval
    rr_retry_bytes = rdata_bytes[idx + 8: idx + 12] 
    rr_retry = int.from_bytes(rr_retry_bytes, 'big')

    # Query traitment - extract Expire limit 
    rr_expire_bytes = rdata_bytes[idx + 12: idx + 16] 
    rr_expire = int.from_bytes(rr_expire_bytes, 'big')

    # Query traitment - extract Minimum TTL 
    rr_minttl_bytes = rdata_bytes[idx + 16: idx + 20]
    rr_minttl = int.from_bytes(rr_minttl_bytes, 'big')

    return {"Primary name server": rdata_server,
            "Responsive authority's mailbox": rdata_mail,
            "Serial number": rr_serial,
            "Refresh interval": rr_refresh,
            "Retry interval": rr_retry,
            "Expire limit ": rr_expire, 
            "extract Minimum TTL ": rr_minttl
            }

def get_rdata_AAAA(cursor, dns_packet): 
    """
    Extract the IPV6 Network Address of the Ressource Record from the RR’s rdata field and return it.


    :param cursor: The position in packet byte array where the analysing should start
    :param dns_packet: The  packet received to analysis
    :type cursor: integer
    :type dns_packet: array of bytes


    :return: Dictionary with a single key ‘IPV6 address’ whose value is the IPV6 Network Address 
    string of rdata ressource record
    :return type: Dict
    """

    #initialization of the dictionary which will contain the address
    dict_address={}
    print(dns_packet)
    #delimitation of the bytes to be translated
    data_bytes = dns_packet[cursor :cursor + 16]
    print(type(data_bytes[0:2]))
    #variable where we get each part of the IP address to assemble it
    rdata_AAAA = hex(int.from_bytes(data_bytes[0:2],"big"))[2::]+":" +str(hex(int.from_bytes(data_bytes[2:4],"big")))[2::] + ":" + str(hex(int.from_bytes(data_bytes[4:6],"big")))[2::] +":"+str(hex(int.from_bytes(data_bytes[6:8],"big")))[2::] +":" + str(hex(int.from_bytes(data_bytes[8:10],"big")))[2::] +":"+str(hex(int.from_bytes(data_bytes[10:12],"big")))[2::] +":" + str(hex(int.from_bytes(data_bytes[12:14],"big")))[2:0] +":"+str(hex(int.from_bytes(data_bytes[14:16],"big")))[2:0]
    dict_address["address_IPv6"] = rdata_AAAA
    return dict_address
