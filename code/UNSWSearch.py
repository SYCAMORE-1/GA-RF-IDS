import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import normalize
from sklearn.preprocessing import MinMaxScaler, StandardScaler, Imputer
import random
from deap import base
from deap import creator
from deap import tools
from itertools import groupby

from sklearn.metrics import roc_curve, auc

import warnings
import collections

from imblearn.over_sampling import SMOTE

import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore", category=FutureWarning, module="sklearn", lineno=245)
"""
A method to do the machine learning part of training and testing the classifier
and to return the classifier metrics
"""
import pickle

INITPOP = 10
trainfilepath = 'UNSW-NB15/Rebuild_UNSW_NB15_training_set.csv'
testfilepath = './UNSW-NB15/Rebuild_UNSW_NB15_testing_set.csv'
featurepath = './UNSW-NB15/features.txt'
testfeaturepath = './UNSW-NB15/importantFeatures.txt'
all_featurepath = './UNSW-NB15/all_features.txt'

_RECONNAISSANCE = 1
_EXPLOITS = 2
_FUZZERS = 3
_WORMS = 4
_GENERIC = 5
_SHELLCODE = 6
_DOS = 7
_ANALYSIS = 8
_BACKDOOR = 9

clf = RandomForestClassifier(bootstrap=True, class_weight=None, criterion='gini',
                             max_depth=10, max_features='auto', max_leaf_nodes=None,
                             min_impurity_decrease=0.0, min_impurity_split=None,
                             min_samples_leaf=1, min_samples_split=2,
                             min_weight_fraction_leaf=0.0, n_estimators=100, n_jobs=3,
                             oob_score=False, random_state=0, verbose=0, warm_start=False)


def saveModel():
    s = pickle.dumps(clf)
    f = open('./UNSW-NB15/rf.txt', 'wb')
    f.write(s)
    f.close()


def loadModel():
    f = open('./UNSW-NB15/rf.txt', 'rb+')
    s = f.read()
    temp_clf = pickle.loads(s)
    return temp_clf


def readFearures(path):
    c = []
    file = open(path, 'r')
    col = file.read().split('\n')
    file.close()
    for i in col:
        if i != '':
            c.append(i)
    return c


def writeFeature(path, importantFeatures):
    f = open(path, 'w')
    for i in range(len(importantFeatures)):
        if importantFeatures[i] != 'result':
            f.write(importantFeatures[i])
            if i != (len(importantFeatures) - 1):
                f.write('\n')
    f.close()


def showFeatureImportance(feature_importance, features):
    x = '_BACKDOOR' + '\n'
    sorted_idx = np.argsort(feature_importance)
    plt.figure(figsize=(20, 15))
    plt.barh(range(len(sorted_idx)), feature_importance[sorted_idx], align='center')
    n = np.array(features)[sorted_idx]
    for i in sorted_idx[::-1]:
        x = x + str(i+1)+'  '+str(np.array(features)[i])+'\n'
    x = x + '\n'
    out = open('./UNSW-NB15/fig/features_in_all_kind.txt', 'a')
    out.writelines('\n')
    out.writelines(x)
    out.close()
    plt.yticks(range(len(sorted_idx)), np.array(features)[sorted_idx])
    plt.xlabel('Importance')
    plt.title('Feature importances')
    plt.draw()
    plt.savefig('./UNSW-NB15/fig/imp_f_BACKDOOR.png')
    # plt.show()


def validateTestData(df, features):
    trainData = readData(trainfilepath, featurepath)
    train_X = trainData[features]
    train_Y = trainData['result']
    over_samples = SMOTE(random_state=60)
    over_samples_x, over_samples_y = over_samples.fit_sample(train_X, train_Y)
    y = pd.DataFrame(over_samples_y)
    print(y[0].value_counts())
    clf.fit(over_samples_x, over_samples_y)

    # saveModel()
    test_x = df[features]
    expected = df['result']
    score = clf.score(test_x, expected)
    print('score: ', score)
    # print('feature_importances_: ', clf.feature_importances_)
    showFeatureImportance(clf.feature_importances_, features)
    # c = loadModel()
    prediction = clf.predict(test_x)
    TP = 0
    TN = 0
    FP = 0
    FN = 0
    Reconnaissance = 0
    Exploits = 0
    Fuzzers = 0
    Worms = 0
    Generic = 0
    Shellcode = 0
    DoS = 0
    Analysis = 0
    Backdoor = 0
    for i in range(0, len(prediction)):
        if int(expected[i]) > 0:  # expected is attack
            if int(prediction[i]) == 0:  # predection is not attack
                FN = FN + 1
            else:  # predection is also attack
                TP = TP + 1
                # ['Normal', 'Reconnaissance', 'Exploits', 'Fuzzers', 'Worms', 'Generic', 'Shellcode', 'DoS', 'Analysis', 'Backdoor']
                # int(expected[i]) == int(prediction[i]) and
                if int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 1:
                    Reconnaissance = Reconnaissance + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 2:
                    Exploits = Exploits + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 3:
                    Fuzzers = Fuzzers + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 4:
                    Worms = Worms + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 5:
                    Generic = Generic + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 6:
                    Shellcode = Shellcode + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 7:
                    DoS = DoS + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 8:
                    Analysis = Analysis + 1
                elif int(expected[i]) == int(prediction[i]) and int(prediction[i]) == 9:
                    Backdoor = Backdoor + 1
        else:  # expected is not attack
            if int(prediction[i]) == 0:  # predection is also not attack
                TN = TN + 1
            else:  # predection is attack
                FP = FP + 1
    accuracy = (TP + TN) / len(df)
    recall = TP / (TP + FN)
    precision = TP / (TP + FP)
    fpr = FP / (FP + TN)

    print(expected.value_counts())
    # acc_Reconnaissance = Reconnaissance / expected.value_counts()['1']
    # acc_Exploits = Exploits / expected.value_counts()['2']
    # acc_Fuzzers = Fuzzers / expected.value_counts()['3']
    # acc_Worms = Worms / expected.value_counts()['4']
    # acc_Generic = Generic / expected.value_counts()['5']
    # acc_Shellcode = Shellcode / expected.value_counts()['6']
    # acc_DoS = DoS / expected.value_counts()['7']
    # acc_Analysis = Analysis / expected.value_counts()['8']
    # acc_Backdoor = Backdoor / expected.value_counts()['9']
    acc_Reconnaissance = Reconnaissance / 10491
    acc_Exploits = Exploits / 33393
    acc_Fuzzers = Fuzzers / 18184
    acc_Worms = Worms / 130
    acc_Generic = Generic / 40000
    acc_Shellcode = Shellcode / 1133
    acc_DoS = DoS / 12264
    acc_Analysis = Analysis / 2000
    acc_Backdoor = Backdoor / 1746
    #
    x = '_BACKDOOR' + '\n'
    print('accuracy: ', accuracy)
    x = x + 'accuracy' + str(accuracy) + '\n'
    print('recall: ', recall)
    x = x + 'recall' + str(recall) + '\n'
    print('precision: ', precision)
    x = x + 'precision' + str(precision) + '\n'
    print('fpr: ', fpr)
    x = x + 'fpr' + str(fpr) + '\n'

    print('acc_Reconnaissance: ', acc_Reconnaissance)
    x = x + 'acc_Reconnaissance' + str(acc_Reconnaissance) + '\n'
    print('acc_Exploits: ', acc_Exploits)
    x = x + 'acc_Exploits' + str(acc_Exploits) + '\n'
    print('acc_Fuzzers: ', acc_Fuzzers)
    x = x + 'acc_Fuzzers' + str(acc_Fuzzers) + '\n'
    print('acc_Worms: ', acc_Worms)
    x = x + 'acc_Worms' + str(acc_Worms) + '\n'
    print('acc_Generic: ', acc_Generic)
    x = x + 'acc_Generic' + str(acc_Generic) + '\n'
    print('acc_Shellcode: ', acc_Shellcode)
    x = x + 'acc_Shellcode' + str(acc_Shellcode) + '\n'
    print('acc_DoS: ', acc_DoS)
    x = x + 'acc_DoS' + str(acc_DoS) + '\n'
    print('acc_Analysis: ', acc_Analysis)
    x = x + 'acc_Analysis' + str(acc_Analysis) + '\n'
    print('acc_Backdoor: ', acc_Backdoor)
    x = x + 'acc_Backdoor' + str(acc_Backdoor) + '\n'

    out = open('./UNSW-NB15/fig/result.txt', 'a')
    out.writelines('\n')
    out.writelines(x)
    out.close()
    # showing roc curve
    expected_list = expected.copy()
    for v in range(len(expected_list)):
        if int(expected_list[v]) > 0:
            expected_list[v] = 1
    l = []
    for i in expected_list:
        l.append(int(i))
    y_score = clf.predict_proba(df[features])
    s = 1 - y_score[:, 0]
    fpr, tpr, thresholds = roc_curve(l, 1 - y_score[:, 0])
    roc_auc = auc(fpr, tpr)

    plt.title('ROC Validation')
    plt.plot(fpr, tpr, 'b', label='AUC = %0.2f' % roc_auc)
    plt.legend(loc='lower right')
    plt.plot([0, 1], [0, 1], 'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.savefig('./UNSW-NB15/fig/_BACKDOOR roc curve.png')
    # plt.show()
    a = 1


def trainTestData(df, pd, features):
    train, test = df[df['is_train'] == True], df[df['is_train'] == False]
    train = train.reset_index()
    test = test.reset_index()
    # target = pd.factorize(train['result'])[0] ????
    target = train['result']
    clf.fit(train[features], target)
    # expected = pd.factorize(test['result'])[0]
    prediction = clf.predict(test[features])
    expected = test['result']

    TP = 0
    TN = 0
    FP = 0
    FN = 0

    for i in range(0, len(prediction)):
        if int(expected[i]) > 0:  # expected is attack
            if int(prediction[i]) == 0:  # predection is not attack
                FN = FN + 1
            else:  # predection is also attack
                TP = TP + 1
        else:  # expected is not attack
            if int(prediction[i]) == 0:  # predection is also not attack
                TN = TN + 1
            else:  # predection is attack
                FP = FP + 1
    accuracy = (TP + TN) / len(test)
    recall = TP / (TP + FN)
    precision = TP / (TP + FP)
    fpr = FP / (FP + TN)
    return accuracy, precision, recall, fpr


"""
Fitness function
Select the features
use stratified k-fold validation
get the metrics from the classifier
calculate the average fitness and evaluate
"""

g_accuracy = []
g_tpr = []
g_fpr = []


def evaluateIndividual(df, features, ind):
    feat = []
    # binary to feature decoding
    l = len(features)
    for i in range(0, len(features)):
        # print(ind[i])
        if str(ind[i]) == '1':
            feat.append(features[i])
    features = feat
    # If feature list is empty / Null check
    if not features:
        return 0
    else:
        X = df[features]
        y = df['result']
        accuracy_list = []
        precision_list = []
        recall_list = []
        fpr_list = []

        skf = StratifiedKFold(n_splits=2)
        for train_index, test_index in skf.split(X, y):
            df.loc[train_index.tolist(), 'is_train'] = True
            df.loc[test_index.tolist(), 'is_train'] = False
            accuracy, recall, precision, fpr = trainTestData(df, pd, features)
            accuracy_list.append(accuracy)
            precision_list.append(precision)
            recall_list.append(recall)
            fpr_list.append(fpr)

        fin_accuracy = sum(accuracy_list) / len(accuracy_list)
        fin_precision = sum(precision_list) / len(precision_list)
        fin_recall = sum(recall_list) / len(recall_list)
        fin_fpr = sum(fpr_list) / len(fpr_list)
        fin_f1 = (2 * fin_precision * fin_recall) / (fin_precision + fin_recall)

        """fin_fitness = (0.6 * fin_accuracy) + (0.2 * fin_precision) + (0.2 * fin_recall)"""
        g_accuracy.append(fin_accuracy)
        g_fpr.append(fin_fpr)
        g_tpr.append(fin_recall)

        # fitness function
        fin_fitness = (0.6 * fin_accuracy) + (0.4 * fin_f1) - 100 * fin_fpr
        print("fin_accuracy:", fin_accuracy, " fin_f1:", fin_f1, " fin_fpr:", fin_fpr, " fin_fitness:", fin_fitness)
        return fin_fitness


# Global data frame initialize to null
# Global to have a copy of the data for next iterations
# globaldataframe = pd.DataFrame({'A': []})


def readData(filepath, featurePath):
    # global globaldataframe
    if 1:
        # First time called, to load the data into program
        # Constants used for mapping to numbers

        # # KDDCUP99
        # filepath = 'kddcup.data_10_percent_corrected'
        # protocol = ['icmp', 'tcp', 'udp']
        # service = ['http', 'smtp', 'finger', 'domain_u', 'auth', 'telnet', 'ftp', 'eco_i', 'ntp_u', 'ecr_i', 'other',
        #            'private', 'pop_3', 'ftp_data', 'rje', 'time', 'mtp', 'link', 'remote_job', 'gopher', 'ssh', 'name',
        #            'whois', 'domain', 'login', 'imap4', 'daytime', 'ctf', 'nntp', 'shell', 'IRC', 'nnsp', 'http_443',
        #            'exec', 'printer', 'efs', 'courier', 'uucp', 'klogin', 'kshell', 'echo', 'discard', 'systat',
        #            'supdup', 'iso_tsap', 'hostnames', 'csnet_ns', 'pop_2', 'sunrpc', 'uucp_path', 'netbios_ns',
        #            'netbios_ssn', 'netbios_dgm', 'sql_net', 'vmnet', 'bgp', 'Z39_50', 'ldap', 'netstat', 'urh_i', 'X11',
        #            'urp_i', 'pm_dump', 'tftp_u', 'tim_i', 'red_i']
        # flag = ['flag', 'SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH']
        # result = ['normal.', 'buffer_overflow.', 'loadmodule.', 'perl.', 'neptune.', 'smurf.', 'guess_passwd.', 'pod.',
        #           'teardrop.', 'portsweep.', 'ipsweep.', 'land.', 'ftp_write.', 'back.', 'imap.', 'satan.', 'phf.',
        #           'nmap.', 'multihop.', 'warezmaster.', 'warezclient.', 'spy.', 'rootkit.']

        # NSL_KDD
        # filepath = 'Rebuild_KDDTrain+.txt'
        # protocol = ['icmp', 'tcp', 'udp']
        # service = ['aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain',
        #            'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data',
        #            'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001',
        #            'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp',
        #            'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp',
        #            'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i',
        #            'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup',
        #            'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp',
        #            'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50']
        # flag = ['flag', 'SF', 'S1', 'REJ', 'S2', 'S0', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'OTH', 'SH']
        # result = ['normal', 'buffer_overflow', 'loadmodule', 'perl', 'neptune', 'smurf', 'guess_passwd', 'pod',
        #           'teardrop', 'portsweep', 'ipsweep', 'land', 'ftp_write', 'back', 'imap', 'satan', 'phf',
        #           'nmap', 'multihop', 'warezmaster', 'warezclient', 'spy', 'rootkit']

        # UNSW-NB15

        protocol = ['igp', 'udp', 'hmp', 'ipnip', 'ipcomp', 'gre', 'iplt', 'bbn-rcc', 'iso-ip', 'narp', 'ipv6-opts',
                    'sccopmce', 'ipv6', 'vmtp', 'vines', 'visa', 'argus', 'iatp', 'mux', 'rdp', 'gmtp', 'larp', 'cphb',
                    'snp', 'ipx-n-ip', 'cpnx', 'uti', 'stp', 'pvp', 'idpr-cmtp', 'wsn', 'micp', 'nsfnet-igp', 'ipip',
                    'cftp', 'isis', 'mhrp', 'kryptolan', 'sm', 'qnx', 'ippc', 'skip', 'mtp', 'dcn', 'ipv6-route',
                    'merit-inp', 'pup', 'smp', 'trunk-1', 'encap', 'any', 'sat-mon', 'pim', 'ptp', 'iso-tp4', 'pri-enc',
                    'mfe-nsp', 'trunk-2', 'pnni', 'emcon', 'dgp', 'leaf-1', 'fc', 'pgm', 'ib', 'ip', 'bna', 'ax.25',
                    'a/n', 'sep', 'chaos', 'sdrp', 'srp', 'arp', 'ipv6-frag', 'leaf-2', 'vrrp', 'swipe', 'idpr',
                    'sat-expak', 'ttp', 'sctp', 'crudp', 'egp', 'compaq-peer', 'secure-vmtp', 'tlsp', 'unas', 'ddx',
                    'aris', 'rvd', 'irtp', 'fire', 'igmp', 'zero', 'xnet', 'netblt', 'ospf', 'ifmp', 'tcp', 'wb-mon',
                    'etherip', 'il', 'ddp', 'mobile', 'prm', 'xtp', '3pc', 'ipv6-no', 'aes-sp3-d', 'eigrp', 'rsvp',
                    'ggp', 'br-sat-mon', 'xns-idp', 'l2tp', 'sun-nd', 'pipe', 'nvp', 'idrp', 'ipcv', 'i-nlsp', 'scps',
                    'crtp', 'tp++', 'tcf', 'cbt', 'wb-expak', 'sprite-rpc', 'sps', 'st2', 'icmp', 'rtp']

        service = ['http', 'ssl', 'ssh', 'ftp', 'radius', 'dns', 'pop3', 'ftp-data', 'snmp', 'dhcp', '-', 'irc', 'smtp']

        state = ['CON', 'CLO', 'ACC', 'REQ', 'RST', 'FIN', 'INT', 'ECO', 'PAR', 'URN', 'no']
        result = ['Normal', 'Reconnaissance', 'Exploits', 'Fuzzers', 'Worms', 'Generic', 'Shellcode', 'DoS', 'Analysis',
                  'Backdoor']

        # opening the features list and reading
        # please change the path accordingly
        col = readFearures(featurePath)
        data = []

        # opening the dataset, mapping the data to values and adding to data frame
        # please change the path accordingly

        with open(filepath) as fp:
            line = fp.readline()
            while line:
                data_array = line.split('\n')[0].split(',')
                data_array[1] = protocol.index(data_array[1])
                data_array[2] = service.index(data_array[2])
                data_array[3] = state.index(data_array[3])
                data_array[42] = result.index(data_array[42])
                if int(data_array[42]) != _BACKDOOR:
                    data_array[42] = 0
                data.append(data_array)
                line = fp.readline()
        n = np.array(data)
        featureData, r = np.split(n, [42], 1)

        # featureData_s = normalize(featureData, norm='l2')  # L2

        # std = StandardScaler()
        # featureData_s = std.fit_transform(featureData)

        mm = MinMaxScaler()
        featureData_s = mm.fit_transform(featureData)

        fin_n = np.concatenate((featureData_s, r), axis=1)
        globaldataframe = pd.DataFrame(fin_n, columns=col)

    return globaldataframe


def main():
    # creator.create("FitnessMax", base.Fitness, weights=(1.0,))
    # creator.create("Individual", list, fitness=creator.FitnessMax)
    #
    # toolbox = base.Toolbox()
    # # Attribute generator
    # toolbox.register("attr_bool", random.randint, 0, 1)
    # # Structure initializers
    # toolbox.register("individual", tools.initRepeat, creator.Individual,
    #                  toolbox.attr_bool, 42)
    # toolbox.register("population", tools.initRepeat, list, toolbox.individual)
    #
    # df = readData(trainfilepath, featurepath)
    # features = df.columns[:42]
    #
    # def evalOneMax(individual):
    #     return evaluateIndividual(df, features, individual),
    #
    # toolbox.register("evaluate", evalOneMax)
    # toolbox.register("mate", tools.cxTwoPoint)
    # toolbox.register("mutate", tools.mutFlipBit, indpb=0.05)
    # toolbox.register("select", tools.selTournament, tournsize=3)
    # print("start")
    # pop = toolbox.population(n=INITPOP)
    #
    # fitnesses = list(map(toolbox.evaluate, pop))
    # for ind, fit in zip(pop, fitnesses):
    #     ind.fitness.values = fit
    # # CXPB  is the probability with which two individualsare crossed
    # # MUTPB is the probability for mutating an individual
    # CXPB, MUTPB = 0.75, 0.3
    #
    # fits = [ind.fitness.values[0] for ind in pop]
    #
    # # Variable keeping track of the number of generations
    # g = 0
    # # Begin the evolution
    # maxfitness = []
    # meanfitness = []
    # # while max(fits) < 0.999999 and g < 100:
    # while g < 100:
    #     # A new generation
    #     g = g + 1
    #     print("-- Generation %i --" % g)
    #
    #     # Select the next generation individuals
    #     offspring = toolbox.select(pop, len(pop))
    #     # Clone the selected individuals
    #     offspring = list(map(toolbox.clone, offspring))
    #     # Apply crossover and mutation on the offspring
    #     for child1, child2 in zip(offspring[::2], offspring[1::2]):
    #         if random.random() < CXPB:
    #             toolbox.mate(child1, child2)
    #             del child1.fitness.values
    #             del child2.fitness.values
    #
    #     for mutant in offspring:
    #         if random.random() < MUTPB:
    #             toolbox.mutate(mutant)
    #             del mutant.fitness.values
    #
    #     # Evaluate the individuals with an invalid fitness
    #     invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
    #     fitnesses = map(toolbox.evaluate, invalid_ind)
    #     for ind, fit in zip(invalid_ind, fitnesses):
    #         ind.fitness.values = fit
    #     pop[:] = offspring
    #     # Gather all the fitnesses in one list and print the stats
    #     fits = [ind.fitness.values[0] for ind in pop]
    #
    #     length = len(pop)
    #     mean = sum(fits) / length
    #     sum2 = sum(x * x for x in fits)
    #     std = abs(sum2 / length - mean ** 2) ** 0.5
    #     maxfitness.append(max(fits))
    #     meanfitness.append(mean)
    #     print("  Min %s" % min(fits))
    #     print("  Max %s" % max(fits))
    #     print("  Avg %s" % mean)
    #     print("  Std %s" % std)
    #     grouped_maxfit = [(k, sum(1 for i in g)) for k, g in groupby(maxfitness)]
    #     last_group = grouped_maxfit[len(grouped_maxfit) - 1]
    #     # exit condition , when the last 10 generations have the same max fitness
    #     if ((last_group[0] == max(fits)) and (last_group[1] >= 10)):
    #         break
    #
    # # Plotting the data into graph
    # plt.plot(meanfitness)
    # plt.ylabel('mean fitness')
    # plt.savefig('./UNSW-NB15/fig/meanfitness.png')
    # plt.show()
    #
    # plt.plot(maxfitness)
    # plt.ylabel('max fitness')
    # plt.savefig('./UNSW-NB15/fig/maxfitness.png')
    # # plt.show()
    #
    # plt.plot(g_accuracy)
    # plt.ylabel('g_accuracy')
    # plt.savefig('./UNSW-NB15/fig/g_accuracy.png')
    # plt.show()
    #
    # plt.plot(g_fpr)
    # plt.ylabel('g_fpr')
    # plt.savefig('./UNSW-NB15/fig/g_fpr.png')
    # plt.show()
    #
    # plt.plot(g_tpr)
    # plt.ylabel('g_tpr')
    # plt.savefig('./UNSW-NB15/fig/g_tpr.png')
    # plt.show()
    #
    # maxfitpopulation = 0
    # maxfit = max(fits)
    #
    # # Decoding the features from the Binary population
    # aggregatepop = []
    # for ind, fit in zip(pop, fits):
    #     if fit == maxfit:
    #         indlist = []
    #         for x in ind:
    #             indlist.append(x)
    #         if aggregatepop == []:
    #             aggregatepop = indlist
    #         else:
    #             aggregatepop = [sum(x) for x in zip(aggregatepop, indlist)]
    #         maxfitpopulation = maxfitpopulation + 1
    # print("*************IMPORTANT FEATURES ARE*****************")
    # importantFeatures = []
    # for indcount, feature in zip(aggregatepop, features):
    #     if (indcount / maxfitpopulation) > 0.49:
    #         print(feature)
    #         importantFeatures.append(feature)
    # print("****************************************************")
    # print(aggregatepop)
    # print(maxfitpopulation)
    #
    # writeFeature(testfeaturepath, importantFeatures)
    features = readFearures(all_featurepath)
    testData = readData(testfilepath, featurepath)
    validateTestData(testData, features)


main()
# uncomment below part to evaluate the complete set of features.
"""
df=readData()
features = df.columns[:41]
print(evaluateIndividual(df,features,"11111111111111111111111111111111111111111"))
"""
