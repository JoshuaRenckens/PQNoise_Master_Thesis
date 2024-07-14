import os
import math
import subprocess

def run_tests(to_execute, to_save, delay, loss):
    path = ""
    file_addition = ""
    if to_execute == "PQ_TLS":
        path = "./TLS/"
    elif to_execute == "Hybrid_TLS":
        #TODO don't have executing hybrid TLS set up yet
        path = "./TLS/"
    else:
        path = "./Noise_c/"

    client_command = [
        'ip', 'netns', 'exec', 'cli_ns', 'taskset', '-c', '3', 'nice', '-n', '-20',
        path + '' + file_addition + 'client', to_execute
    ]
    server_command = [
        'ip', 'netns', 'exec', 'srv_ns', 'taskset', '-c', '2', 'nice', '-n', '-20',
        path + '' + file_addition + 'server', to_execute
    ]

    server_output = open('./Results/server_'+to_save, 'a+')
    server_output.write('Runs with delay: '+str(delay)+' and loss rate: '+str(loss)+'\n');
    print(" Running: " + " ".join(server_command))
    res_server= subprocess.Popen(
        server_command,
        stdout=server_output,
        stderr=subprocess.PIPE,
        cwd='.'
    )

    client_output = open('./Results/client_' + to_save, 'a+')
    client_output.write('Runs with delay: '+str(delay)+' and loss rate: '+str(loss)+'\n');
    print(" Running: " + " ".join(client_command))
    res_client = subprocess.run(
        client_command,
        stdout=client_output,
        stderr=subprocess.PIPE,
        cwd='.'
    )

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
    
    
n = 0
# ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
for latency_ms in ['2.684', '15.458','39.224', '97.73']:
    n += 1
    
    # Get the round trip time
    #change_qdisc('cli_ns', 'cli_ve', 0, delay=latency_ms)
    #change_qdisc('srv_ns', 'srv_ve', 0, delay=latency_ms)
    #rtt_str = get_rtt()
    #print(rtt)


    for subject in ['NN', 'NK', 'XX']:
        #for pkt_loss in [0, 0.1, 0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 6, 7, 8, 9, 10]:
        for pkt_loss in [0, 1, 3, 5, 10]:
            change_qdisc('cli_ns', 'cli_ve', pkt_loss, delay=latency_ms)
            change_qdisc('srv_ns', 'srv_ve', pkt_loss, delay=latency_ms)
            res = run_tests(subject, 'Results_'+subject+'.txt', latency_ms, pkt_loss)
            if res:
                print("Finished current")
            else:
                print("Error")
