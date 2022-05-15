from cgi import test
import os, sys, random
import numpy as np
import matplotlib.pyplot as plt
import scipy.stats as stats

from sklearn.svm import OneClassSVM
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix

standard_label = {}
hmi = "192.168.1.101"
rtu = "192.168.1.100"

def read_input_file(input_file, standard_dataset=True):
    with open(input_file, 'r') as lines:
        file_content = lines.readlines()
        if standard_dataset:
            global standard_label
            standard_label = file_content[0].strip('\n').split(';')
        content = [line.strip('\n').split(';') for line in file_content]
        return content


def split_standard(content, shuffle=False):
    if shuffle:
        random.shuffle(content)
    return content[0:int(len(content)*0.7)], content[0:int(len(content)*0.3)]


def separate_content(content):
    return [line for line in content if line[2] == hmi], [line for line in content if line[2] == rtu]


def sigma_rule_differences(content, mean_type=True):
    if mean_type:
        return [int(line[standard_label.index("len")]) for line in content]

    data = []
    start = float(content[0][1])
    sum_of_window = 0
    new_packet = False

    for i in range(0, len(content)):
        if float(content[i][1]) > start + WINDOW:
            data.append([sum_of_window/1000, [start, start+WINDOW]])
            sum_of_window = 0
            start += WINDOW
        if float(content[i][6]) != float(content[i - 1][6]):
            new_packet = True
        if new_packet:
            sum_of_window += float(content[i][6])
            new_packet = False

    return data


def sigma_anomaly_detection(com_standard, com_attack):
    mean = np.mean([com[0] for com in com_standard])
    sigma = np.std([com[0] for com in com_standard])

    attack_intervals_detected = []
    for i in range(0, len(com_attack)):
        if float(com_attack[i][0]) < mean - SIGMA_VAL*sigma or float(com_attack[i][0]) > mean + SIGMA_VAL*sigma:
            attack_intervals_detected.append(com_attack[i][1])
    # print(attack_intervals_detected)
    if attack_intervals_detected:
        attack_detected = []
        start_of_attack, end_of_attack = attack_intervals_detected[0]
        for i in range(1, len(attack_intervals_detected)):
            # print(str(start_of_attack) + "\t" + str(end_of_attack))
            if attack_intervals_detected[i][0] == end_of_attack:
                end_of_attack = attack_intervals_detected[i][1]
            else:
                attack_detected.append([start_of_attack, end_of_attack])
                start_of_attack = attack_intervals_detected[i][0]
                end_of_attack = attack_intervals_detected[i][1]
        attack_detected.append([start_of_attack, end_of_attack])

        print(attack_detected)
        return attack_detected


def sigma_rule(com_standard, com_attack):
    plt.figure(figsize=(6, 4))

    mean = np.mean([com[0] for com in com_standard])
    sigma = np.std([com[0] for com in com_standard])

    x = np.linspace(mean - SIGMA_VAL*sigma, mean + SIGMA_VAL*sigma)
    y = stats.norm.pdf(x, mean, sigma)

    y_values = np.full(len(com_standard), 0)
    y_values2 = np.full(len(com_attack), 0.001)

    plt.scatter([com[0] for com in com_standard], y_values)
    plt.scatter([com[0] for com in com_attack], y_values2)
    plt.plot(x, y)
    plt.show()


def box_plot(content_master, content_slave, idx=0):
    correct_column_master = [int(line[idx]) for line in content_master]

    correct_column_slave = [int(line[idx]) for line in content_slave]

    plt.figure(figsize=(6, 4))

    plt.boxplot([correct_column_master, correct_column_slave], labels=["Master","Slave"], notch=True)

    plt.xlabel('Varianty')
    plt.ylabel('Hodnoty')
    plt.title('Boxplot')

    plt.show()
    plt.close()


# DETECTION_DEVICE = "RTU"    # incoming communication from HMI
DETECTION_DEVICE = "HMI"    # incoming communication from RTU

ATTACK = "REPLAY"
# ATTACK = "ATTRIBUTE_CHANGE"
# ATTACK = "REPORT_BLOCK"
# ATTACK = "MASQUERADING"

#   Standard
if DETECTION_DEVICE == "HMI":
    standard = read_input_file(os.path.join(os.getcwd(), "../csv/", "HMI_Standard-ioa.csv"))
else:
    standard = read_input_file(os.path.join(os.getcwd(), "../csv/", "RTU_Standard-ioa.csv"))

h2r, r2h = separate_content(standard)

if ATTACK == "REPLAY":
    if DETECTION_DEVICE == "HMI":
        WINDOW = 60
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "replay_HMI-ioa.csv"), False)
    else:
        WINDOW = 3600
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "replay_RTU-ioa.csv"), False)
elif ATTACK == "ATTRIBUTE_CHANGE":
    WINDOW = 300
    if DETECTION_DEVICE == "HMI":
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "HMI_MITM_corrected-ioa.csv"), False)
    else:
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "RTU_MITM_corrected-ioa.csv"), False)
elif ATTACK == "REPORT_BLOCK":
    WINDOW = 300
    if DETECTION_DEVICE == "HMI":
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "report_block_HMI-ioa.csv"), False)
    else:
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "report_block_RTU-ioa.csv"), False)
elif ATTACK == "MASQUERADING":
    WINDOW = 400
    if DETECTION_DEVICE == "HMI":
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "masquerading_RTU-ioa.csv"), False)
    else:
        attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "masquerading_HMI-ioa.csv"), False)

attack_h2r, attack_r2h = separate_content(attack)


#   --------------- 3-Sigma method ---------------------------
SIGMA_VAL = 5
if DETECTION_DEVICE == "HMI":
    desired_values_standard = sigma_rule_differences(r2h, False)
    desired_values_attack = sigma_rule_differences(attack_r2h, False)
else:
    desired_values_standard = sigma_rule_differences(h2r, False)
    desired_values_attack = sigma_rule_differences(attack_h2r, False)

sigma_rule(desired_values_standard, desired_values_attack)  # Sigma rule detection
sigma_detected = sigma_anomaly_detection(desired_values_standard, desired_values_attack)

#   --------------- Boxplot method ---------------------------

# hmi_com = sigma_rule_differences(h2r, False)
# rtu_com = sigma_rule_differences(r2h, False)
# box_plot(h2r, r2h)


#   --------------- OneClassSVM method ---------------------------
def split_standard(content):
    return content[0:int(len(content)*0.7)], content[0:int(len(content)*0.3)]


def OneClassSVM_times(content):
    data = []
    counts = []
    average_size = []

    start = float(content[0][1])
    sum_of_window = 0
    new_packet = False
    count = 0

    intervals = []
    types = []
    types_in_window = []
    for i in range(0, len(content)):
        if float(content[i][1]) > start + WINDOW:
            data.append(sum_of_window)
            if count > 0:
                average_size.append(sum_of_window/count)
            counts.append(count)
            count = 0
            sum_of_window = 0
            intervals.append([start, start+WINDOW])
            start += WINDOW
            types.append(types_in_window)
            types_in_window = []
        if float(content[i][6]) != float(content[i - 1][6]):
            new_packet = True
        if new_packet:
            sum_of_window += float(content[i][6])
            count += 1
            new_packet = False
        else:
            types_in_window.append(content[i][10])

    return [data, average_size, counts], intervals, types


def evaluate(model, content, ground_truth, intervals):
    predicted = model.predict(content)
    predicted[predicted == 1] = 1
    predicted[predicted == -1] = 0

    conf_mat = confusion_matrix(ground_truth, predicted)
    tn, fp, fn, tp = confusion_matrix(ground_truth, predicted).ravel()

    predicted = predicted == 1
    ground = ground_truth == 1
    detected = []
    for i in range(0, len(predicted)):
        if predicted[i] != ground[i]:
            detected.append(intervals[i])
    # print(detected)

    print(predicted)
    print(ground)
    print(conf_mat)
    accuracy = (tp + tn) / (tp + tn + fp + fn) * 100
    print("ACCURACY:\t" + str(accuracy))


h2r_train, h2r_test = split_standard(h2r)
r2h_train, r2h_test = split_standard(r2h)

h2r_svm_train, intervals_h2r_train, h2r_train_types = OneClassSVM_times(h2r_train)
r2h_svm_train, intervals_r2h_train, r2h_train_types = OneClassSVM_times(r2h_train)
h2r_svm_test, intervals_h2r_test, h2r_test_types = OneClassSVM_times(h2r_test)
r2h_svm_test, intervals_r2h_test, r2h_test_types = OneClassSVM_times(r2h_test)



# svm_model = OneClassSVM(kernel='rbf', gamma=0.1, nu=0.015)
svm_model = OneClassSVM(kernel='rbf', gamma=0.001, nu=0.07)
# svm_model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.5)
# svm_model = OneClassSVM(kernel='rbf', gamma=0.001, nu=0.0001)
s_data = [(value, count) for [value, avg, count] in [[data[i] for data in r2h_svm_train] for i in range(0, len(r2h_svm_train[0]))]]
test_data = [[value, count] for [value, avg, count] in [[data[i] for data in r2h_svm_test] for i in range(0, len(r2h_svm_test[0]))]]

#######################################################
# s_data = [pair for pair in zip(s_data, r2h_train_types)]
# print(r2h_train_types)


#######################################################
svm_model.fit(s_data)

ground_truth = np.full(len(test_data), 1)
evaluate(svm_model, test_data, ground_truth, intervals_r2h_test)


h2r_svm_anomaly, intervals_attack_h2r, h2r_attack_types = OneClassSVM_times(attack_h2r)
r2h_svm_anomaly, intervals_attack_r2h, r2h_attack_types = OneClassSVM_times(attack_r2h)
a_data = [(value, count) for [value, avg, count] in [[data[i] for data in r2h_svm_anomaly] for i in range(0, len(r2h_svm_anomaly[0]))]]


ground_truth_is_correct = np.full(len(desired_values_attack), 1)
# ground_truth_sigma_based = np.full(len(desired_values_attack), 1)
# for i in range(0, len(desired_values_attack)):
#     for j in range(0, len(sigma_detected)):
#         if desired_values_attack[i][1][0] >= sigma_detected[j][0] and desired_values_attack[i][1][1] <= sigma_detected[j][1]:
#             ground_truth_sigma_based[i] = 0

evaluate(svm_model, a_data, ground_truth_is_correct, intervals_attack_r2h)

