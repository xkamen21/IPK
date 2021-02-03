import socket
import sys
import re

HOST = '127.0.0.1'
PORT = int(sys.argv[1])

if PORT < 1024:
    print("Error: Bad Port, choose port frome <1024,65536>")
    exit(-1)
    pass

if PORT > 65535:
    print("Error: Bad Port, choose port frome <1024,65536>")
    exit(-1)
    pass

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

try:
    while True:
        conn, addr = server.accept()
        data = conn.recv(1024)
        data = data.decode()
        lines = data.replace(" ","")
        lines = lines.splitlines()
        string = lines[0]

        regex = re.compile(r'\b[g|G]{1}[e|E]{1}[t|T]{1}')
        GET = regex.search(string)
        regex = re.compile(r'\b[p|P]{1}[o|O]{1}[s|S]{1}[t|T]{1}')
        POST = regex.search(string)

        if GET:
            i = 0
            a = 0
            b = 0
            while i<len(string):
                if string[i]=='=':

                    if a == 0:
                        a = i+1
                        pass

                    pass

                if string[i]=='&':
                    b = i
                    break
                    pass

                i = i+1
                pass
            hostname = string[a:b]
            i = len(string) - 1

            while i>0:
                if string[i] == '=':
                    a=i+1;
                    break
                    pass

                i = i-1
                pass


            switcher = ""
            bool2 = False;
            regex = re.compile(r'\b[a|A]{1}\b')
            bool2 = regex.search(string[a])
            if bool2:
                switcher = "A"
                pass
            else:
                regex = re.compile(r'\b[p|P]{1}[t|T]{1}[r|R]{1}\b')
                bool2 = regex.search(string[a:a+3])
                if bool2:
                    switcher = "PTR"
                    pass
                pass

            if switcher.upper() == "A":
                #regex pro URL adresu: \b[-a-zA-Z0-9@:%._\+~#=]+\.[a-zA-Z]{1,3}\b
                url_regex = re.compile(r'\b[-a-zA-Z0-9@:%._\+~#=]+\.[a-zA-Z]{1,3}$')
                bool = url_regex.search(hostname)
                if bool != None:
                    try:
                        IPAddr = socket.gethostbyname(hostname)
                        result = hostname + ":" + switcher + "=" + IPAddr + "\n"
                        result = "HTML/1.1 200 OK\r\n\r\n"+result
                    except socket.gaierror:
                        result = "HTML/1.1 404 Not Found\n"
                    pass
                else:
                    result = "HTML/1.1 400 Bad Request\n"
                    pass
                pass

            elif switcher.upper() == "PTR":
                #regex pro IP adresu: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
                IP_regex = re.compile(r'\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b')
                bool = IP_regex.search(hostname)
                if bool != None:
                    try:
                        IPAddr = socket.gethostbyaddr(hostname)
                        result = hostname + ":" + switcher + "=" + IPAddr[0] + "\n"
                        result = "HTML/1.1 200 OK\r\n\r\n"+result

                    except socket.herror:
                        result = "HTML/1.1 404 Not Found\n"
                    pass

                else:
                    result = "HTML/1.1 400 Bad Request\n"
                    pass
                pass
            else:
                result = "HTML/1.1 400 Bad Request\n"
                pass

            pass #if GET
        elif POST:
            counter_valid = 0
            counter_bad = 0
            counter_not = 0
            finall = ""
            for line in lines[7:]:
                empty_row=len(line)
                if empty_row == 0:
                    counter_bad = counter_bad + 1
                    continue
                    pass
                i = len(line)-1
                while i>0:
                    if line[i] == ':':
                        break
                        pass

                    i = i-1
                    pass


                switcher = ""
                bool2 = False;
                regex = re.compile(r'\b[a|A]{1}\b')
                bool2 = regex.search(line[i:]) #########
                if bool2:
                    switcher = "A"
                    pass
                else:
                    regex = re.compile(r'\b[p|P]{1}[t|T]{1}[r|R]{1}\b')
                    bool2 = regex.search(line[i:])
                    if bool2:
                        switcher = "PTR"
                        pass
                    pass

                if switcher.upper() == "A":
                    #regex pro URL adresu: \b[-a-zA-Z0-9@:%._\+~#=]+\.[a-zA-Z]{1,3}\b
                    url_regex = re.compile(r'\b[-a-zA-Z0-9@:%._\+~#=]+\.[a-zA-Z]{1,3}\b')
                    bool = url_regex.search(line[:i])
                    if bool != None:
                        try:
                            IPAddr = socket.gethostbyname(line[:i])
                            result = line[:i] + ":" + switcher + "=" + IPAddr + "\n"
                            finall = finall + result
                            counter_valid = counter_valid+1
                        except socket.gaierror:
                            counter_not = counter_not+1
                        pass
                    else:
                        counter_bad = counter_bad+1
                        pass
                    pass

                if switcher.upper() == "PTR":
                    #regex pro IP adresu: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
                    IP_regex = re.compile(r'\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b')
                    bool = IP_regex.search(line[:i])
                    if bool != None:
                        try:
                            IPAddr = socket.gethostbyaddr(line[:i])
                            result = line[:i] + ":" + switcher + "=" + IPAddr[0] + "\n"
                            finall = finall + result
                            counter_valid = counter_valid+1

                        except socket.herror:
                            counter_not = counter_not+1
                        pass

                    else:
                        counter_bad = counter_bad + 1
                        pass
                    pass
                pass
            pass
        else:
            result = "HTML/1.1 405 Method Not Allowed\n"
            pass

        if GET:
            conn.send(result.encode())
            pass
        elif POST:
            if counter_valid > 0:
                finall = "HTML/1.1 200 OK\r\n\r\n" + finall
                pass
            elif len(lines)-7 == counter_not :
                finall = "HTML/1.1 404 Not Found\r\n\r\n" + finall
                pass
            else:
                finall = "HTML/1.1 400 Bad Request\r\n\r\n" + finall
                pass
            conn.send(finall.encode())
            pass

        conn.close()

except KeyboardInterrupt:
    sys.exit()
