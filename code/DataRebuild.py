# remove the last column in NSLKDD dataset
def rebuild_NSLKDD(input_file, output_file):

    protocol = ['icmp', 'tcp', 'udp']

    service = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain',
               'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data',
               'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001',
               'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp',
               'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp',
               'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i',
               'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup',
               'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp',
               'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50']
    flag = ['flag', 'SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH']
    result = ['normal',  # 0

              # DOS   1
              'back',  # 1
              'land',  # 2
              'neptune',  # 3
              'pod',  # 4
              'smurf',  # 5
              'teardrop',  # 6
              'apache2',  # 7
              'mailbomb',  # 8
              'processtable',  # 9
              'udpstorm',  # 10

              # PROBE   2
              'satan',  # 11
              'ipsweep',  # 12
              'nmap',  # 13
              'portsweep',  # 14
              'mscan',  # 15
              'saint',  # 16

              # R2L   3
              'guess_passwd',  # 17
              'ftp_write',  # 18
              'imap',  # 19
              'phf',  # 20
              'multihop',  # 21
              'warezmaster',  # 22
              'warezclient',  # 23
              'spy',  # 24
              'named',  # 25
              'sendmail',  # 26
              'snmpgetattack',  # 27
              'snmpguess',  # 28
              'worm',  # 29
              'xlock',  # 30
              'xsnoop',  # 31

              # U2R   4
              'buffer_overflow',  # 32
              'loadmodule',  # 33
              'perl',  # 34
              'rootkit',  # 35
              'httptunnel',  # 36
              'ps',  # 37
              'sqlattack',  # 38
              'xterm'  # 39
              ]

    f = open(input_file, 'r')
    out = open(output_file, 'w')
    for line in f.readlines():
        x = ''
        a = line.split(",")
        for i in range(0, 41):
            # if i == 1:
            #     a[1] = protocol.index(a[1])
            # elif i == 2:
            #     a[2] = service.index(a[2])
            # elif i == 3:
            #     a[3] = flag.index(a[3])
            x = x + str(a[i]) + ","
        # a[41] = result.index(a[41])
        # if int(a[41]) != 0:
        #     if int(a[41]) - 10 <= 0:
        #         a[41] = 1
        #     elif int(a[41]) - 16 <= 0:
        #         a[41] = 2
        #     elif int(a[41]) - 31 <= 0:
        #         a[41] = 3
        #     elif int(a[41]) - 39 <= 0:
        #         a[41] = 4
        x = x + str(a[41]) + "\n"
        out.writelines(x)
    f.close()
    out.close()


def collect_NonNum_Feature_In_UNSWNB(input_file):
    proto = set()
    service = set()
    state = set()
    attack_cat = set()
    f = open(input_file, 'r')
    for line in f.readlines():
        a = line.split(",")
        proto.add(a[2])
        service.add(a[3])
        state.add(a[4])
        attack_cat.add(a[43])
    print('proto:', proto)
    print('service:', service)
    print('state:', state)
    print('attack_cat:', attack_cat)


def rebuild_UNSW_NB15(input_file, output_file):
    f = open(input_file, 'r')
    out = open(output_file, 'w')
    for line in f.readlines():
        x = ''
        a = line.split(",")
        for i in range(1, 43):
            x = x + a[i] + ","
        x = x + a[43] + "\n"
        out.writelines(x)
    f.close()
    out.close()

def main():
    # 重构NSL数据集
    # input_file = './NSL-KDD/KDDTrain+.txt'
    # output_file = './NSL-KDD/Rebuild_KDDTrain+.csv'
    input_file = './NSL-KDD/KDDTest+.txt'
    output_file = './NSL-KDD/Rebuild_KDDTest+.csv'

    rebuild_NSLKDD(input_file, output_file)

    # 统计UNSW的字符型特征
    # input_file = 'UNSW_NB15_training_set.csv'
    # collect_NonNum_Feature_In_UNSWNB(input_file)

    # 重构UNSW数据集
    input_file = 'UNSW-NB15/UNSW_NB15_testing_set.csv'
    output_file = 'UNSW-NB15/Rebuild_UNSW_NB15_testing_set.csv'
    # input_file = 'UNSW-NB15/UNSW_NB15_training_set.csv'
    # output_file = 'UNSW-NB15/Rebuild_UNSW_NB15_training_set.csv'
    #rebuild_UNSW_NB15(input_file, output_file)



main()
