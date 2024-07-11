import os
import math
import subprocess

def run_tests(to_execute, to_save):
    path = ""
    file_addition = ""
    if to_execute == "PQ_Noise":
        path = "./Noise_c/"
    elif to_execute == "Hybrid_Noise":
        path = "./Noise_c/"
        file_addition = "hyb"
    elif to_execute == "PQ_TLS":
        path = "./TLS/"
    elif to_execute == "Hybrid_TLS":
        #TODO don't have executing hybrid TLS set up yet
        path = "./TLS/"
    else:
        return 0

    client_command = [
        'ip', 'netns', 'exec', 'cli_ns', 'taskset', '-c', '3', 'nice', '-n', '-20',
        path + '' + file_addition + 'client'
    ]
    server_command = [
        'ip', 'netns', 'exec', 'srv_ns', 'taskset', '-c', '2', 'nice', '-n', '-20',
        path + '' + file_addition + 'server'
    ]

    server_output = open('./Results/server_'+to_save, 'w')
    print(" Running: " + " ".join(server_command))
    res_server= subprocess.Popen(
        server_command,
        stdout=server_output,
        stderr=subprocess.PIPE,
        cwd='.'
    )

    client_output = open('./Results/client_' + to_save, 'w')
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
    
n = 0
# ['2.684ms', '15.458ms', '39.224ms', '97.73ms']
for latency_ms in ['2.684', '15.458']:
    n += 1
    # To get actual (emulated) RTT
    #change_qdisc('cli_ns', 'cli_ve', 0, delay=latency_ms)
    #change_qdisc('srv_ns', 'srv_ve', 0, delay=latency_ms)
    # Some code to ping and get the actual RTT.


    for subject in ['PQ_Noise']:
        #for pkt_loss in [0, 0.1, 0.5, 1, 1.5, 2, 2.5, 3, 4, 5, 6, 7, 8, 9, 10]:
        for pkt_loss in [0, 1, 3, 5]:
            change_qdisc('cli_ns', 'cli_ve', pkt_loss, delay=latency_ms)
            change_qdisc('srv_ns', 'srv_ve', pkt_loss, delay=latency_ms)
            res = run_tests(subject, '_lat_'+str(n)+"_loss_"+str(pkt_loss)+"_"+subject+".txt")
            if res:
                print("Finished current")
            else:
                print("Error")
