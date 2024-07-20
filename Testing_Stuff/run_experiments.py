import os
import math
import subprocess
import time

def run_tests(to_execute, to_save, delay, loss, subject):
    path = ''
    file_addition = ''
    if subject == "TLS":
        path = "./TLS/"
    elif subject == "Noise":
        path = "./Noise_c/"
        if to_execute.endswith('hyb', 2):
        	print("Got it");
        	file_addition = 'hyb'

    client_command = [
        'ip', 'netns', 'exec', 'cli_ns',
        path + '' + file_addition + 'client', to_execute, str(loss)
    ]
    
    if subject != 'TLS':
	    server_command = [
		'ip', 'netns', 'exec', 'srv_ns',
		path + '' + file_addition + 'server', to_execute, str(loss)
	    ]

	    server_output = open('./Results/server_'+to_save, 'a+')
	    #server_output.write('Runs with delay: '+str(delay)+' and loss rate: '+str(loss)+'\n')
	    server_output.flush()
	    print(" Running: " + " ".join(server_command))
	    # Run the server component non-blocking
	    res_server= subprocess.Popen(
		server_command,
		stdout=server_output,
		stderr=subprocess.PIPE,
		cwd='.'
	    )

    client_output = open('./Results/client_' + to_save, 'a+')
    #client_output.write('Runs with delay: '+str(delay)+' and loss rate: '+str(loss)+'\n')
    client_output.flush()
    print(" Running: " + " ".join(client_command))
    # Run the client component blocking
    res_client = subprocess.run(
        client_command,
        stdout=client_output,
        stderr=subprocess.PIPE,
        cwd='.'
    )
	
    if subject != 'TLS':
    	if res_server.stderr:
        	print(res_server.stderr)

    if res_client.stderr:
        print(res_client.stderr)

    return 1

def change_qdisc(ns, dev, pkt_loss, delay):
    if pkt_loss == 0:
        command = [
            'ip', 'netns', 'exec', ns,
            'tc', 'qdisc', 'change',
            'dev', dev, 'root', 'netem',
            'limit', '1000',
            'delay', str(delay)+'ms',
            'rate', '1000mbit'
        ]
    else:
        command = [
            'ip', 'netns', 'exec', ns,
            'tc', 'qdisc', 'change',
            'dev', dev, 'root', 'netem',
            'limit', '1000',
            'loss', '{0}%'.format(pkt_loss),
            'delay', str(delay)+'ms',
            'rate', '1000mbit'
        ]

    print(" Running " + " ".join(command))

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd='.'
    )
    

def get_rtt():
    command = [
        'ip', 'netns', 'exec', 'cli_ns',
        'ping', '10.0.0.1', '-c', '30'
    ]

    print(" > " + " ".join(command))
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd='.'
    )
    
    print(result)

    result_fmt = result.splitlines()[-1].split("/")
    return result_fmt[4].replace(".", "p")
    
    
# Possible subjects: Noise, TLS
subject = 'TLS'
# ['2.684', '15.458', '39.224', '97.73']
for latency_ms in ['2.684']:
    
    # Get the round trip time
    #change_qdisc('cli_ns', 'cli_ve', 0, delay=latency_ms)
    #change_qdisc('srv_ns', 'srv_ve', 0, delay=latency_ms)
    #rtt_str = get_rtt()
    #print(rtt)
    
    # If we are running TLS run the server component early, since it is kept open
    if subject == 'TLS':
	    server_command = [
		'ip', 'netns', 'exec', 'srv_ns',
		'./TLS/server'
	    ]
	    
	    res_server= subprocess.Popen(
		server_command,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		cwd='.'
	    )
	    time.sleep(1)

    # To execute a hybrid Noise pattern: NNhyb, NKhyb etc. to execute PQTLS or hybrid TLS just enter 'kyber512', 'x25519_kyber512' etc.
    # Didn't make a large array to iterate through since I didn't want to execute them all together, since that would take too long.
    for to_execute in ['X25519', 'kyber512', 'x25519_kyber512']:
        #for pkt_loss in [0, 0.1, 0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 6, 7, 8, 9, 10]:
        # 0, 1, 3, 5, 8, 10, 13, 15, 18, 20
        for pkt_loss in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]:
            change_qdisc('cli_ns', 'cli_ve', pkt_loss, delay=latency_ms)
            change_qdisc('srv_ns', 'srv_ve', pkt_loss, delay=latency_ms)
            res = run_tests(to_execute, 'Results_'+to_execute+'.txt', latency_ms, pkt_loss, subject)
            if res:
                print("Finished current")
            else:
                print("Error")   
                
    if subject == 'TLS':
	    res_server.terminate()
