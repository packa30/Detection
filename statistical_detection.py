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


#   --------------- OneClassSVM method ---------------------------
def split_standard(content):
    return content[0:int(len(content) * 0.7)], content[0:int(len(content) * 0.3)]


def OneClassSVM_times(content):
    data = []
    counts = []
    average_size = []

    start = float(content[0][1])
    sum_of_window = 0
    new_packet = False
    count = 1

    intervals = []
    types = []
    types_in_window = []
    for i in range(1, len(content)):
        if float(content[i][1]) > start + WINDOW:
            data.append(sum_of_window)
            average_size.append(sum_of_window / count)
            counts.append(count)
            count = 1
            sum_of_window = 0
            intervals.append([start, start + WINDOW])
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


def evaluate(model, content, ground, intervals):
    predicted = model.predict(content)
    predicted[predicted == 1] = 1
    predicted[predicted == -1] = 0

    # conf_mat = confusion_matrix(ground, predicted)
    tn, fp, fn, tp = confusion_matrix(ground, predicted).ravel()

    detected = []
    for i in range(0, len(predicted) - 1):
        if predicted[i] != ground[i] and predicted[i + 1] != ground[i + 1]:
            detected.append(intervals[i])

    if detected:
        anomaly = []
        start_of_attack, end_of_attack = detected[0]
        for i in range(1, len(detected)):
            if int(detected[i][0]) == int(end_of_attack):
                end_of_attack = detected[i][1]
            else:
                if end_of_attack - start_of_attack > WINDOW + 1:
                    anomaly.append([start_of_attack, end_of_attack])
                start_of_attack = detected[i][0]
                end_of_attack = detected[i][1]
        if end_of_attack - start_of_attack > WINDOW + 1:
            anomaly.append([start_of_attack, end_of_attack])
        print(anomaly)

    # print(predicted)
    # print(ground_truth)
    # print(conf_mat)
    accuracy = (tp + tn) / (tp + tn + fp + fn) * 100
    print("Model accuracy:\t" + str(accuracy))


DETECTION_DEVICES = ["HMI", "RTU"]
# DETECTION_DEVICE = "HMI"    # incoming communication from RTU
# ATTACKS = ["REPLAY", "ATTRIBUTE_CHANGE", "REPORT_BLOCK", "MASQUERADING"]
ATTACKS = ["REPORT_BLOCK"]
# ATTACKS = []
svm_model = OneClassSVM(kernel='rbf', gamma=0.001, nu=0.07)
svm_window = 60

for ATTACK in ATTACKS:
    for DETECTION_DEVICE in DETECTION_DEVICES:
        #   Standard
        if DETECTION_DEVICE == "HMI":
            standard = read_input_file(os.path.join(os.getcwd(), "../csv/", "HMI_Standard-ioa.csv"))
        else:
            standard = read_input_file(os.path.join(os.getcwd(), "../csv/", "RTU_Standard-ioa.csv"))

        h2r, r2h = separate_content(standard)

        if ATTACK == "REPLAY":
            print("------------------------------------------------------------------------")
            print("Replay attack detection")
            if DETECTION_DEVICE == "HMI":
                print("RTU -> HMI packets replayed, detectable on HMI device")
                WINDOW = 500
                attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "replay_HMI-ioa.csv"), False)
            else:
                print("HMI -> RTU packets replayed, detectable on RTU device")
                WINDOW = 2000
                attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "replay_RTU-ioa.csv"), False)
        elif ATTACK == "ATTRIBUTE_CHANGE":
            print("------------------------------------------------------------------------")
            print("Attribute change detection")
            WINDOW = 500
            if DETECTION_DEVICE == "HMI":
                print("RTU -> HMI packets changed, detectable on HMI or RTU device - HMI device detection")
                attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "HMI_MITM_corrected-ioa.csv"), False)
            else:
                print("RTU -> HMI packets changed, detectable on HMI or RTU device - RTU device detection")
                attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "RTU_MITM_corrected-ioa.csv"), False)

            svm_model = OneClassSVM(kernel='rbf', gamma=0.001, nu=0.07)
            svm_window = 500
        elif ATTACK == "REPORT_BLOCK":
            WINDOW = 500
            if DETECTION_DEVICE == "HMI":
                print("------------------------------------------------------------------------")
                print("Block report message detection")
                print("RTU -> HMI packets changed, detectable on HMI device")
                attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "report_block_HMI-ioa.csv"), False)
            else:
                attack = []
                # Can not be detected
                # attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "report_block_RTU-ioa.csv"), False)
        elif ATTACK == "MASQUERADING":
            WINDOW = 500
            if DETECTION_DEVICE == "HMI":
                print("------------------------------------------------------------------------")
                print("Masquerading attack detection")
                print("New HMI device connected, detectable on RTU device")
                attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "masquerading_RTU-ioa.csv"), False)
            else:
                attack = []
                # Can not be detected
                # attack = read_input_file(os.path.join(os.getcwd(), "../csv/Attacks/", "masquerading_HMI-ioa.csv"), False)
        else:
            attack = []

        if attack:
            attack_h2r, attack_r2h = separate_content(attack)

            #   --------------- 3-Sigma method ---------------------------
            print("\n3-sigma method detection detected intervals")
            SIGMA_VAL = 3
            if DETECTION_DEVICE == "HMI":
                desired_values_standard = sigma_rule_differences(r2h, False)
                desired_values_attack = sigma_rule_differences(attack_r2h, False)
            else:
                desired_values_standard = sigma_rule_differences(h2r, False)
                desired_values_attack = sigma_rule_differences(attack_h2r, False)

            # sigma_rule(desired_values_standard, desired_values_attack)  # Sigma rule detection figure
            sigma_detected = sigma_anomaly_detection(desired_values_standard, desired_values_attack)
            print("\n")

            #   --------------- OneClassSVM method ---------------------------
            WINDOW = svm_window
            h2r_train, h2r_test = split_standard(h2r)
            r2h_train, r2h_test = split_standard(r2h)
            h2r_svm_train, intervals_h2r_train, h2r_train_types = OneClassSVM_times(h2r_train)
            r2h_svm_train, intervals_r2h_train, r2h_train_types = OneClassSVM_times(r2h_train)
            h2r_svm_test, intervals_h2r_test, h2r_test_types = OneClassSVM_times(h2r_test)
            r2h_svm_test, intervals_r2h_test, r2h_test_types = OneClassSVM_times(r2h_test)
            h2r_svm_anomaly, intervals_attack_h2r, h2r_attack_types = OneClassSVM_times(attack_h2r)
            r2h_svm_anomaly, intervals_attack_r2h, r2h_attack_types = OneClassSVM_times(attack_r2h)

            # svm_model = OneClassSVM(kernel='rbf', gamma=0.001, nu=0.07)
            # svm_model = OneClassSVM(kernel='rbf', gamma=0.001, nu=0.0001)

            if DETECTION_DEVICE == "HMI":
                s_data = [(value, count) for [value, avg, count]
                          in [[data[i] for data in r2h_svm_train] for i in range(0, len(r2h_svm_train[0]))]]
                test_data = [[value, count] for [value, avg, count]
                             in [[data[i] for data in r2h_svm_test] for i in range(0, len(r2h_svm_test[0]))]]
                a_data = [(value, count) for [value, avg, count]
                          in [[data[i] for data in r2h_svm_anomaly] for i in range(0, len(r2h_svm_anomaly[0]))]]
                test_intervals = intervals_r2h_test
                anomaly_intervals = intervals_attack_r2h
            else:
                s_data = [(value, count) for [value, avg, count]
                          in [[data[i] for data in h2r_svm_train] for i in range(0, len(h2r_svm_train[0]))]]
                test_data = [[value, count] for [value, avg, count]
                             in [[data[i] for data in h2r_svm_test] for i in range(0, len(h2r_svm_test[0]))]]
                a_data = [(value, count) for [value, avg, count]
                          in [[data[i] for data in h2r_svm_anomaly] for i in range(0, len(h2r_svm_anomaly[0]))]]
                test_intervals = intervals_h2r_test
                anomaly_intervals = intervals_attack_h2r

            svm_model.fit(s_data)

            #   --------------- OneClassSVM - eval via test data---------------------------
            ground_truth = np.full(len(test_data), 1)
            print("\nOneClassSVM classification - detected intervals - Model testing communication")
            evaluate(svm_model, test_data, ground_truth, test_intervals)
            print('\n')

            #   --------------- OneClassSVM - eval comm with anomaly ---------------------------
            #   --------------- is_correct - shows accuracy if ground is expected to be standard com ---------------------------
            ground_truth = np.full(len(a_data), 1)

            #   --------------- sigma_based - shows accuracy if ground is right ---------------------------
            # for i in range(0, len(a_data)):
            #     for j in range(0, len(sigma_detected)):
            #         if anomaly_intervals[i][0] >= sigma_detected[j][0] and anomaly_intervals[i][1] <= sigma_detected[j][1]:
            #             ground_truth[i] = 0
            print("\nOneClassSVM classification - detected intervals - Anomaly communication")
            evaluate(svm_model, a_data, ground_truth, anomaly_intervals)
            print('\n')
            print("------------------------------------------------------------------------\n")

#######################################################


rep_block_train = []
rep_block_test = []
rep_block_anomaly = []


def types_data_switch(content, content_types):
    new_dataset = []
    for i in range(0, len(content_types)):
        for j in range(0, len(content_types[i])):
            if content_types[i][j].isdigit():
                new_dataset.append([int(content_types[i][j]), content[i][0]])
    return new_dataset


svm_model = OneClassSVM(kernel='rbf', gamma=0.1, nu=0.015)
rep_block_train = types_data_switch(s_data, r2h_train_types)
rep_block_test = types_data_switch(test_data, r2h_test_types)
rep_block_anomaly = types_data_switch(a_data, r2h_attack_types)


# for i in range(0, len(s_data)):
#     count = 0
#     types = 0
#     for j in range(0, len(r2h_train_types[i])):
#         if r2h_train_types[i][j].isdigit():
#             count += 1
#             types += int(r2h_train_types[i][j])
#     rep_block_train.append([s_data[i][0], types/count])
#
# for i in range(0, len(test_data)):
#     count = 0
#     types = 0
#     for j in range(0, len(r2h_test_types[i])):
#         if r2h_test_types[i][j].isdigit():
#             count += 1
#             types += int(r2h_test_types[i][j])
#     rep_block_test.append([test_data[i][0], types/count])
#
# for i in range(0, len(a_data)):
#     count = 0
#     types = 0
#     for j in range(0, len(r2h_attack_types[i])):
#         if r2h_attack_types[i][j].isdigit():
#             count += 1
#             types += int(r2h_attack_types[i][j])
#     rep_block_anomaly.append([a_data[i][0], types/count])

svm_model.fit(rep_block_train)

ground_truth = np.full(len(test_data), 1)
evaluate(svm_model, rep_block_test, ground_truth, intervals_r2h_test)

ground_truth = np.full(len(a_data), 1)
evaluate(svm_model, rep_block_anomaly, ground_truth, intervals_attack_r2h)

# print(rep_block_train)
# print(rep_block_test)

#######################################################




