#© 2023 Nokia
#Licensed under the Creative Commons Attribution Non Commercial 4.0 International license
#SPDX-License-Identifier: CC-BY-NC-4.0
#

import random
import torch
import numpy as np
import pandas as pd
from collections import defaultdict
import regex as re
from tqdm import tqdm
from ast import literal_eval



def set_seed(seed = 42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.backends.cudnn.deterministic = True

LINUX_SEMANTIC_EVENT_MAP = {
    "961489c4": "DEVICE_NODE_CREATE",
    "09789b2b": "SESSION_OPEN",
    "27624832": "SESSION_CLOSE",
    "32a4064e": "DNS_LISTEN_IPV4",
    "b780997e": "UNKNOWN_USER",
    "cb0e911a": "AUTH_FAIL",
    "d38ec4eb": "FTP_CONNECTION",
    "980efd56": "TTY_PEER_DIED",
    "6aadc992": "FTP_CONNECTION",
    "3d002f62": "DEVICE_NODE_REMOVE",
    "c148af6a": "TTY_TIMEOUT",
    "593496d9": "DNS_STOP_LISTEN",
    "ee259d46": "FTP_PEER_DISCONNECT",
    "426520a8": "UNKNOWN_USER_TIMEOUT",
    "f2487cd5": "SYSTEM_INFO",
    "dea5ca56": "KERBEROS_AUTH_FAIL",
    "99132f5d": "KERNEL_TIME_SYNC",
    "5dc1b8dd": "EXPLOIT_PAYLOAD_ATTEMPT",
}

def linux_semantic_token(row):
    event_id = str(row["EventId"])
    content = str(row["Content"]).lower()
    component = str(row["Component"]).lower()

    # Special contextual handling
    if event_id == "8691a3d6":
        if "user=root" in content:
            return "ROOT_AUTH_FAIL"
        return "AUTH_FAIL_USER"

    # Exact EventId map
    if event_id in LINUX_SEMANTIC_EVENT_MAP:
        return LINUX_SEMANTIC_EVENT_MAP[event_id]

    # Fallback text rules
    if "sudo" in component:
        return "SUDO_EVENT"

    if "crond" in component:
        return "CRON_EVENT"

    if "sshd" in component:
        return "SSHD_EVENT"

    return f"EVENT_{event_id}"

#

def linux_rule_based_labeling(df):
    """
    Light row-level labels only.
    Most Linux attack behavior should be labeled later at the window level.
    """
    df = df.copy()
    df['Label'] = 0

    content = df['Content'].astype(str).str.lower()

    strong_single_line_patterns = [
        'maximum authentication attempts exceeded',
        'not in sudoers',
        'authentication token manipulation error',
        'connection closed by invalid user',
    ]

    for pattern in strong_single_line_patterns:
        df.loc[content.str.contains(pattern, regex=False, na=False), 'Label'] = 1

    return df

def label_linux_window(tokens):
    auth_fails = (
        tokens.count("AUTH_FAIL")
        + tokens.count("ROOT_AUTH_FAIL")
        + tokens.count("AUTH_FAIL_USER")
        + tokens.count("KERBEROS_AUTH_FAIL")
    )
    unknown_users = (
        tokens.count("UNKNOWN_USER")
        + tokens.count("UNKNOWN_USER_TIMEOUT")
    )
    ftp_connections = tokens.count("FTP_CONNECTION")
    ftp_disconnects = tokens.count("FTP_PEER_DISCONNECT")

    exploit_attempts = tokens.count("EXPLOIT_PAYLOAD_ATTEMPT")
    dns_stop = tokens.count("DNS_STOP_LISTEN")

    # Strong direct malicious indicator
    if exploit_attempts >= 1:
        return 1

    # Auth abuse
    if auth_fails >= 5:
        return 1

    if unknown_users >= 3:
        return 1

    if "ROOT_AUTH_FAIL" in tokens and auth_fails >= 2:
        return 1

    if auth_fails >= 2 and ("SESSION_OPEN" in tokens or "ROOT_SESSION_OPEN" in tokens):
        return 1

    # FTP burst behavior
    if ftp_connections >= 10:
        return 1

    # Many disconnect/errors after burst
    if ftp_connections >= 5 and ftp_disconnects >= 3:
        return 1

    # DNS service disruption
    if dns_stop >= 2:
        return 1

    return 0

def hdfs_blk_process(df, blk_label_dict):
    data_dict = defaultdict(list)
    for idx, row in tqdm(df.iterrows()):
        blkId_list = re.findall(r'(blk_-?\d+)', row['Content'])
        blkId_set = set(blkId_list)
        for blk_Id in blkId_set:
            if blk_Id not in data_dict:
                data_dict[blk_Id] = [row['EventId']]
            else:
                data_dict[blk_Id].append(row["EventId"])

    data_df = pd.DataFrame(list(data_dict.items()), columns=['BlockId', 'EventSequence'])

    data_df["Label"] = data_df["BlockId"].apply(
        lambda x: blk_label_dict.get(x))  # add label to the sequence of each blockid

    return data_df

def sliding_window(df, options):
    if options['dataset_name'] == 'BGL':
        df['datatime'] = pd.to_datetime(df['Time'], format='%Y-%m-%d-%H.%M.%S.%f')
    if options['dataset_name'] == 'Thunderbird':
        df['datatime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'], format='%Y-%m-%d %H:%M:%S')
    if options['dataset_name'] == 'OpenStack':
        df['datatime'] = pd.to_datetime(df['Time'] + ' ' + df['Pid'], format='%Y-%m-%d %H:%M:%S.%f', errors='coerce')
        df['datatime'] = df['datatime'].fillna(method='ffill')
    if options['dataset_name'] == 'Linux':
        df['datatime'] = pd.to_datetime(
            df['Month'].astype(str) + ' ' + df['Day'].astype(str) + ' ' + df['Time'].astype(str),
            format='%b %d %H:%M:%S',
            errors='coerce'
        )
        df['datatime'] = df['datatime'].fillna(method='ffill')
    # token_col = "SemanticToken" if options["dataset_name"] == "Linux" and "SemanticToken" in df.columns else "EventId"
    if (
    options["dataset_name"] == "Linux"
    and options.get("use_semantic_tokens", True)
    and "SemanticToken" in df.columns
    ):
        token_col = "SemanticToken"
    else:
        token_col = "EventId"
    df['timestamp'] = df['datatime'].values.astype(np.int64) // 10 ** 9
    df = df.sort_values('timestamp')

    df.set_index('timestamp', drop=False, inplace=True)
    start_time = df.timestamp.min()
    end_time = df.timestamp.max()
    new_data = []
    while start_time < end_time:
        df_window = df.loc[start_time:start_time+options["window_size"]]
        if len(df_window) > 1:  # Only consider windows with more than one value
            if len(df_window) > options['max_lens']:
                start_time_inner = df_window.timestamp.min()
                end_time_inner = df_window.timestamp.max()

                while (end_time_inner - start_time_inner) > options['max_lens']:
                    df_window_inner = df_window.loc[start_time_inner:start_time_inner+options['max_lens']]

                    # tokens = df_window_inner[token_col].values.tolist()
                    # label_org = df_window_inner['Label'].values.tolist()
                    # label = label_linux_window(tokens) if options['dataset_name'] == 'Linux' else df_window_inner['Label'].max()
                    # new_data.append([
                    #     label_org,
                    #     label,
                    #     tokens
                    # ])
                    sequence_tokens = df_window_inner[token_col].values.tolist()
                    label_org = df_window_inner['Label'].values.tolist()

                    if options['dataset_name'] == 'Linux':
                        label_tokens = df_window_inner['SemanticToken'].values.tolist()
                        label = label_linux_window(label_tokens)
                    else:
                        label = df_window_inner['Label'].max()

                    new_data.append([
                        label_org,
                        label,
                        sequence_tokens
                    ])

                    start_time_inner += options['max_lens'] // 2
            else:

                # tokens = df_window[token_col].values.tolist()
                # label_org = df_window['Label'].values.tolist()
                # label = label_linux_window(tokens) if options['dataset_name'] == 'Linux' else df_window['Label'].max()
                # new_data.append([
                #     label_org,
                #     label,
                #     tokens
                # ])
                sequence_tokens = df_window[token_col].values.tolist()
                label_org = df_window['Label'].values.tolist()

                if options['dataset_name'] == 'Linux':
                    label_tokens = df_window['SemanticToken'].values.tolist()
                    label = label_linux_window(label_tokens)
                else:
                    label = df_window['Label'].max()

                new_data.append([
                    label_org,
                    label,
                    sequence_tokens
                ])

        start_time += options['step_size']

    print('there are %d instances (sliding windows) in this dataset\n' % len(new_data))
    return pd.DataFrame(new_data, columns=['Label_org', 'Label', 'EventSequence'])



def preprocessing(preprocessing=True, dataset_name='HDFS', options=None):
    if preprocessing:

        if dataset_name == 'Linux':
            print("Preprocessing Linux dataset")
            df = pd.read_csv('./datasets/Linux.log_structured.csv', engine='c', na_filter=False, memory_map=True)
            df = linux_rule_based_labeling(df)
            df["SemanticToken"] = df.apply(linux_semantic_token, axis=1)
            print("use_semantic_tokens:", options.get("use_semantic_tokens", True))

            if options.get("use_semantic_tokens", True):
                print(df["SemanticToken"].value_counts().head(20))
            else:
                print(df["EventId"].value_counts().head(20))
            print(df['Label'].value_counts())
            print('There are %d instances in this dataset\n' % len(df))

            new_df = sliding_window(df, options)
            # new_df.to_csv('./datasets/Linux.W{}.S{}.csv'.format(
            #     options['window_size'],
            #     options['step_size']
            # ))

            suffix = "semantic" if options.get("use_semantic_tokens", True) else "eventid"

            new_df.to_csv('./datasets/Linux.W{}.S{}.{}.csv'.format(options['window_size'], options['step_size'], suffix))

            del new_df


        elif dataset_name == 'HDFS':
            print("Preprocessing HDFS dataset")
            df = pd.read_csv('./datasets/HDFS.log_structured.csv', engine='c', na_filter=False, memory_map=True)
            blk_df = pd.read_csv('./datasets/anomaly_label.csv', engine='c', na_filter=False, memory_map=True)
            blk_label_dict = {}
            for _, row in tqdm(blk_df.iterrows()):
                blk_label_dict[row['BlockId']] = 1 if row['Label'] == 'Anomaly' else 0

            hdfs_df = hdfs_blk_process(df, blk_label_dict)
            hdfs_df.to_csv('./datasets/HDFS.BLK.csv')
            del df
            del blk_label_dict
            del blk_df
        elif dataset_name == 'BGL':
            print("Preprocessing BGL dataset")
            df = pd.read_csv('./datasets/BGL.log_structured.csv', engine='c', na_filter=False, memory_map=True)
            print('There are %d instances in this dataset\n' % len(df))
            df['Label'] = df['Label'].ne('-').astype(int)
            new_df = sliding_window(df, options)
            new_df.to_csv('./datasets/BGL.W{}.S{}.csv'.format(options['window_size'],
                                                              options['step_size']))
            del new_df

        elif dataset_name == 'Thunderbird':
            print("Preprocessing Thunderbird dataset")
            df = pd.read_csv('./datasets/Thunderbird.log_structured.csv', engine='c', na_filter=False, memory_map=True)
            df['Label'] = df['Label'].ne('-').astype(int)
            print('There are %d instances in this dataset\n' % len(df))
            new_df = sliding_window(df, options)
            new_df.to_csv('./datasets/Thunderbird.W{}.S{}.csv'.format(options['window_size'],
                                                                      options['step_size']))
            del new_df

        elif dataset_name == 'OpenStack':
            print("Preprocessing OpenStack dataset")
            df = pd.read_csv('./datasets/OpenStack.log_structured.csv', engine='c', na_filter=False, memory_map=True)
            with open('./datasets/OpenStack_anomaly_labels.txt', 'r') as f:
                abnormal_label = f.readlines()
            lst_abnormal_label = []
            for i in abnormal_label[2:]:
                lst_abnormal_label.append(i.strip())
            df['Label'] = 0
            for i in range(len(lst_abnormal_label)):
                for j in range(len(df)):
                    if lst_abnormal_label[i] in df['Content'][j]:
                        df['Label'][j] = 1
            print(df['Label'].value_counts())


            print('There are %d instances in this dataset\n' % len(df))
            new_df = sliding_window(df, options)
            new_df.to_csv('./datasets/OpenStack.W{}.S{}.csv'.format(options['window_size'],
                                                                      options['step_size']))
            del new_df

def train_test_split(dataset_name='HDFS', train_samples=5000, seed=42, options=None, dir='.'):
    if dataset_name == 'Linux':
        suffix = "semantic" if options.get("use_semantic_tokens", True) else "eventid"
        df = pd.read_csv(
            dir + '/datasets/Linux.W{}.S{}.{}.csv'.format(options['window_size'], options['step_size'], suffix),
            index_col=0,
            dtype={'Label': int}
        )

        df.EventSequence = df.EventSequence.apply(literal_eval)

        normal_df = df[df['Label'] == 0]
        normal_df = normal_df.sample(frac=1, random_state=seed).reset_index(drop=True)

        anomaly_df = df[df['Label'] == 1]

        effective_train_samples = min(train_samples, max(len(normal_df) - 1, 0))

        train_df = normal_df[:effective_train_samples]
        test_df = pd.concat([normal_df[effective_train_samples:], anomaly_df], ignore_index=True)

        train_df.to_csv(
            dir + '/datasets/Linux.W{}.S{}.train.csv'.format(options['window_size'], options['step_size'])
        )
        test_df.to_csv(
            dir + '/datasets/Linux.W{}.S{}.test.csv'.format(options['window_size'], options['step_size'])
        )

        print(f'datasets contains: {len(df)} windows, {len(normal_df)} normal windows, '
              f'{len(anomaly_df)} anomaly windows')
        print(f'Trianing dataset contains: {len(train_df)} windows')
        print(f'Testing dataset contains: {len(test_df)} windows, '
              f'{len(test_df.loc[test_df["Label"] == 0])} normal windows ,{len(anomaly_df)} anomaly windows')

        return train_df, test_df


    elif dataset_name == 'HDFS':
        hdfs_df = pd.read_csv(dir + '/datasets/HDFS.BLK.csv', index_col=0, dtype={'BlockId': str, 'Label':int})
        hdfs_df.EventSequence = hdfs_df.EventSequence.apply(literal_eval)
        normal_df = hdfs_df[hdfs_df['Label'] == 0]
        normal_df = normal_df.sample(frac=1, random_state=seed).reset_index(drop=True)
        anomaly_df = hdfs_df[hdfs_df['Label'] == 1]
        train_df = normal_df[:train_samples]
        test_df = normal_df[train_samples:].append(anomaly_df)
        train_df.to_csv(dir + '/datasets/HDFS.BLK.train.csv')
        test_df.to_csv(dir + '/datasets/HDFS.BLK.test.csv')
        print(f'datasets contains: {len(hdfs_df)} blocks, {len(normal_df)} normal blocks, '
              f'{len(anomaly_df)} anomaly blocks')
        print(f'Trianing dataset contains: {len(train_df)} blocks')
        print(f'Testing dataset contains: {len(test_df)} blocks, '
              f'{len(test_df.loc[test_df["Label"] == 0])} normal blocks ,{len(anomaly_df)} anomaly blocks')
        return train_df, test_df
    elif dataset_name == 'BGL':
        df = pd.read_csv(dir + '/datasets/BGL.W{}.S{}.csv'.format(options['window_size'], options['step_size']), index_col=0, dtype={'Label': int})
        df.EventSequence = df.EventSequence.apply(literal_eval)
        normal_df = df[df['Label'] == 0]
        normal_df = normal_df.sample(frac=1, random_state=seed).reset_index(drop=True)
        anomaly_df = df[df['Label'] == 1]
        train_df = normal_df[:train_samples]
        test_df = normal_df[train_samples:].append(anomaly_df)
        train_df.to_csv(dir + '/datasets/BGL.W{}.S{}.train.csv'.format(options['window_size'], options['step_size']))
        test_df.to_csv(dir + '/datasets/BGL.W{}.S{}.test.csv'.format(options['window_size'], options['step_size']))
        print(f'datasets contains: {len(df)} windows, {len(normal_df)} normal windows, '
                f'{len(anomaly_df)} anomaly windows')
        print(f'Trianing dataset contains: {len(train_df)} windows')
        print(f'Testing dataset contains: {len(test_df)} windows, '
                f'{len(test_df.loc[test_df["Label"] == 0])} normal windows ,{len(anomaly_df)} anomaly windows')
        return train_df, test_df
    elif dataset_name == 'Thunderbird':
        df = pd.read_csv(dir + '/datasets/Thunderbird.W{}.S{}.csv'.format(options['window_size'], options['step_size']), index_col=0, dtype={'Label': int})
        df.EventSequence = df.EventSequence.apply(literal_eval)
        normal_df = df[df['Label'] == 0]
        normal_df = normal_df.sample(frac=1, random_state=seed).reset_index(drop=True)
        anomaly_df = df[df['Label'] == 1]
        train_df = normal_df[:train_samples]
        test_df = normal_df[train_samples:].append(anomaly_df)
        train_df.to_csv(dir + '/datasets/Thunderbird.W{}.S{}.train.csv'.format(options['window_size'], options['step_size']))
        test_df.to_csv(dir + '/datasets/Thunderbird.W{}.S{}.test.csv'.format(options['window_size'], options['step_size']))
        print(f'datasets contains: {len(df)} windows, {len(normal_df)} normal windows, '
                f'{len(anomaly_df)} anomaly windows')
        print(f'Trianing dataset contains: {len(train_df)} windows')
        print(f'Testing dataset contains: {len(test_df)} windows, '
                f'{len(test_df.loc[test_df["Label"] == 0])} normal windows ,{len(anomaly_df)} anomaly windows')
        return train_df, test_df
    elif dataset_name == 'OpenStack':
        df = pd.read_csv(dir + '/datasets/OpenStack.W{}.S{}.csv'.format(options['window_size'], options['step_size']), index_col=0, dtype={'Label': int})
        df.EventSequence = df.EventSequence.apply(literal_eval)
        normal_df = df[df['Label'] == 0]
        normal_df = normal_df.sample(frac=1, random_state=seed).reset_index(drop=True)
        anomaly_df = df[df['Label'] == 1]
        train_df = normal_df[:train_samples]
        test_df = normal_df[train_samples:].append(anomaly_df)
        train_df.to_csv(dir + '/datasets/OpenStack.W{}.S{}.train.csv'.format(options['window_size'], options['step_size']))
        test_df.to_csv(dir + '/datasets/OpenStack.W{}.S{}.test.csv'.format(options['window_size'], options['step_size']))
        print(f'datasets contains: {len(df)} windows, {len(normal_df)} normal windows, '
                f'{len(anomaly_df)} anomaly windows')
        print(f'Trianing dataset contains: {len(train_df)} windows')
        print(f'Testing dataset contains: {len(test_df)} windows, '
                f'{len(test_df.loc[test_df["Label"] == 0])} normal windows ,{len(anomaly_df)} anomaly windows')
        return train_df, test_df




def get_training_dictionary(df):
    '''Get training dictionary

    Arg:
        df: dataframe of preprocessed sliding windows

    Return:
        dictionary of training datasets
    '''
    dic = {}
    count = 0
    for i in range(len(df)):
        lst = list(df['EventSequence'].iloc[i])
        for j in lst:
            if j in dic:
                pass
            else:
                dic[j] = str(count)
                count += 1
    return dic
