#!/usr/local/bin/python3

import os, sys, subprocess

def run(filepath):
    print("FUCK")
    
    # this is an example on how to run a shell command (iptables for instance) using call (blocking) 
    subprocess.call('iptables -F'.split(' '))
    subprocess.call('iptables -F -t nat'.split(' '))
    subprocess.call('iptables -F -t mangle'.split(' '))
    
    # this is an example on how to run a shell command (echo for instance) using Popen (non blocking) 
    p = subprocess.Popen('echo -n "Welcome To DarkLab" > /root/index.html', shell=True)
    # and wait for this process to terminate
    p.wait()

    subprocess.call('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'.split(' '))
    subprocess.call('iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT'.split(' '))
    subprocess.call('iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT'.split(' '))
    subprocess.call('iptables -t nat -A PREROUTING -p tcp -i eth1 -d 142.1.97.172 --dport 80 -j DNAT --to-destination 10.0.0.3:8080'.split(' '))
    
    # this is an example on how to run a shell command, redirect its output to a pipe and read that pipe while the command is running
    # stderr is redirect to stdout
    # stdout is redirected to the PIPE
    # cwd is the current working directory

    proc = subprocess.Popen('python2.7 -m SimpleHTTPServer 8080', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=r'/root', shell=True)
    for line in iter(proc.stdout.readline, b''):
            decoded = line.decode('utf-8')
            if (decoded.find('flag=') >= 0):
                flag = ''
                index = decoded.find('flag=') + len('flag=')
                proc.terminate()
                while decoded[index] != ' ':
                    flag += decoded[index]
                    index += 1
                with open(filepath, "w") as text_file:
                    print(flag, file=text_file, end='')
                with open('/shared/flag.txt', "w") as t:
                    print(flag, file=t, end='')
                proc.terminate()
                sys.exit(0)
            
# =============================================
# ===== do not modify the code below ==========
# =============================================
    
if __name__ == "__main__":
    import os, sys, getopt
    def usage():
       print ('Usage:	' + os.path.basename(__file__) + ' filepath ')
       sys.exit(2)
    # extract parameters
    try:
         opts, args = getopt.getopt(sys.argv[1:],"h",["help"])
    except getopt.GetoptError as err:
         print(err)
         usage()
         sys.exit(2)
    filepath = args[0] if len(args) > 0 else None
    for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
    if (filepath is None):
        print('filepath is missing\n')
        usage()
    # run the command
    run(filepath)
