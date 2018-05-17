#!/usr/bin/python3
import sys
import time
import io
import subprocess
import threading


def print_pipe(type_pipe,pipe):
    for line in iter(pipe.readline, ''):
         print( "[%s] %s"%(type_pipe,line), )

#fp = os.fdopen( sys.stdout.fileno(), 'wb' )

command = "./read_stdin_forever.py"
#command = "top"
arguments = ""


p = subprocess.Popen( [command, arguments ], bufsize=1024,
                        shell=False,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, close_fds=True)

#my_input_stream  = io.TextIOWrapper( p.stdout, encoding='utf-8')
#my_output_stream = io.TextIOWrapper( p.stdin, encoding='utf-8')

t1 = threading.Thread(target=print_pipe, args=("stdout",p.stdout,))
t1.start()
t2 = threading.Thread(target=print_pipe, args=("stderr",p.stderr,))
t2.start()

the_string = 'Hello World!'
while True :
    sys.stdout.write( the_string.encode( encoding='UTF-8' ) )
#    sys.stdout.write( the_string.encode( encoding='UTF-8' ) )
    time.sleep( 1 )


