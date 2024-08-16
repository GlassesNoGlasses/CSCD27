#!/usr/local/bin/python3

import os, sys, subprocess

def run(filepath):
    
    # this is an example on how to run a shell command (iptables for instance) using call (blocking) 
    subprocess.call('iptables -F'.split(' '))
    subprocess.call('iptables -F -t nat'.split(' '))
    subprocess.call('iptables -F -t mangle'.split(' '))
    
    # this is an example on how to run a shell command (echo for instance) using Popen (non blocking) 
    p = subprocess.Popen('echo -n "hello word" > /root/index.html', shell=True)
    # and wait for this process to terminate
    p.wait()
    
    # this is an example on how to run a shell command, redirect its output to a pipe and read that pipe while the command is running
    # stderr is redirect to stdout
    # stdout is redirected to the PIPE
    # cwd is the current working directory
    proc = subprocess.Popen('python2.7 -m SimpleHTTPServer 8080', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=r'/root', shell=True)
    for line in iter(proc.stdout.readline, b''):
            with open(filepath, "w") as text_file:
                print(line.decode('utf-8'), file=text_file, end='')
            # and then terminate the process and exit the python program with the exit code 0
            # this dummy code is going to stop after the reading the first line
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
