# -*- coding=utf-8 -*-
#!/usr/bin/python

import math
import pickle

accepted_chars = 'abcdefghijklmnopqrstuvwxyz '

pos = dict([(char, idx) for idx, char in enumerate(accepted_chars)])

#去除标点符号
def normalize(line):
    return [c.lower() for c in line if c.lower() in accepted_chars]

#返回normalize后字符串中的每个字母
def ngram(n, l):
    filtered = normalize(l)
    for start in range(0, len(filtered) - n + 1):
        yield ''.join(filtered[start:start + n])

def train():
    k = len(accepted_chars)
    counts = [[10 for i in range(k)] for i in range(k)]

    #序列化训练文件
    for line in open('big.txt'):
        for a, b in ngram(2, line):
            counts[pos[a]][pos[b]] += 1


    for i, row in enumerate(counts):
        s = float(sum(row))
        for j in range(len(row)):
            row[j] = math.log(row[j] / s)

    good_probs = [avg_transition_prob(l, counts) for l in open('good.txt')]
    bad_probs = [avg_transition_prob(l, counts) for l in open('bad.txt')]

    thresh = (min(good_probs) + max(bad_probs)) / 2
    pickle.dump({'mat': counts, 'thresh': thresh}, open('gib_model.pki', 'wb'))

def avg_transition_prob(l, log_prob_mat):
    log_prob = 0.0
    transition_ct = 0
    for a, b in ngram(2, l):
        log_prob += log_prob_mat[pos[a]][pos[b]]
        transition_ct += 1
    return math.exp(log_prob / (transition_ct or 1))

if __name__ == '__main__':
    train()



    
    
