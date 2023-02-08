"""Module use to start the application for DNS resolution."""

from my_dns.dns_resolv import *

if __name__ == '__main__':
    # Menu to choose the type of DNS query
    print("******************************MENU*************************************************")
    print("Type de requete DNS à résoudre ")
    print("1- Type A ")
    print("2- Type NS pour les serveurs DNS ")
    print("3- Type CNAME pour les alias d’un nom de domaine ")#webrt.chalons.univ-reims.fr 
    print("4- Type SOA pour des informations sur les serveurs faisant autorité sur le domaine ")
    print("5- Type PTR pour une résolution inversée à partir de l’adresse IP")
    print("6- Type MX pour les serveurs de messagerie")
    print("7- type AAAA pour les résolutions IPV6")
    print("***********************************************************************************")

    choice = input("Donner le numéro de votre choix de requête : ")
    server=input("Choisir le serveur DNS à interroger : ")

    # For case of 'A' DNS request
    if choice == "1":
        fqdn=input("Donner le FQDN, le nom de domaine ou l'adresse IP à traduire : ")

        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "A")

    # For case of 'NS' DNS request
    if choice == "2":
        fqdn=input("Donner le le nom de domaine pour lequel vous voulez connaitre le serveur DNS qui fait autorité : ")

        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "NS")

    # For case of 'CNAME' DNS request
    if choice == "3":
        fqdn=input("Donner le le nom de domaine pour lequel vous voulez connaitre l'alias de nom de domaine : ")

        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "CNAME")
    
    # For case of 'SOA' DNS request
    if choice == "4":
        fqdn=input("Donner le le nom de domaine pour lequel vous voulez connaitre l'alias de nom de domaine : ")

        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "SOA")

    # Example for another kind of DNS request, the 'PRT' DNS request
    if choice == "5":
        fqdn=input("Donner adresse IP a traduire en FQDN: ")
    
        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "PTR")

    # For case of 'MX' DNS request
    if choice == "6":
        fqdn=input("Donner le le nom de domaine pour lequel vous voulez connaitre le serveur de messagerie: ")

        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "MX")
    
    
    # For case of 'AAAA' DNS request
    if choice == "7":
        fqdn=input("Donner le le nom de domaine pour lequel vous voulez connaitre l'adresse IPv6: ")

        # Prepare the request byte packet
        MESSAGE = set_query(fqdn, "AAAA")

        
    #Sending the query and storing the received response
    data=send_query(MESSAGE, server)

    # Display the data - have to be modified before to extract the datas.
    #print (data)

    
    print(get_rrs(data))
    print('End')
