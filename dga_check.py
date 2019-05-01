#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Author: Homer
# Date: 2018-08-03
# Version: 0.6
# ELK

'''
数据源：ES抽取
判断思路：
1. 计算域名中每个字母出现的随机性熵值，熵值越高随机性越高
2. 判断域名中的英文元音字母所占的比重,判断域名可读性
3. 将域名拆分后根据n-gram排名，排名越低越可疑
4. 满足以上三个条件筛选出来的域名，判断同一个IP一天内发起长度相同且格式相同的域名请求次数超过50次
5. 满足以上条件且同一个IP请求的不相同的域名个数超过5种
6. 判断域名是否为汉语拼音或拼音首字母组成，是则丢弃，形成最终结果
7. 将域名进行whois查询，统计查询比例，从而判断检测准确率

8月2号更新：新增whois查询模块
8月3号更新：基于贪婪算法过滤汉语拼音或拼音首字母组成的域名

待更新：英文单词组成的DGA域名识别

结果：
输出域名、源IP、请求的次数
'''

import requests, time, random, base64, urllib.parse, argparse
import re
import sys,socket
from elasticsearch import Elasticsearch
import json
from collections import Counter
import math
import numpy as np
import whois

import pickle
import gib_detect_train

class dga_check():
	def __init__(self):
		'''
			初始化配置文件设置
		'''

		#参数初始化
		self.parser = argparse.ArgumentParser(description='dga域名检测工具. by Homer.')
		self.parser.add_argument('-i', dest='index', type=str, help='ES index. ex(event_20180801)')
		self.parser.add_argument('-host', dest='eshost', type=str, help='ES ip address and port. ex(http://ip:port/)')
		self.parser.add_argument('-p', dest='path', type=str, help='Your Script Path. ex(/Users/homerqing/Documents/Scripts/Python/DGA/)')
		self.args = self.parser.parse_args()

		#序列化pki文件，元音字母可读性计算
		self.model_data = pickle.load(open('gib_model.pki', 'rb'))

		# Host
#		self.host = 'http://172.16.100.196:9200/'
		self.host = self.args.eshost

		# 脚本路径
		self.path = './'

		# Index
		index_raw = [
		 #   'event_20180505',
		#    'event_20180506',
		 #   sys.argv[2]
		    self.args.index,
		]

		# 实例化
		self.es = Elasticsearch(self.host)

		#查询事件
		self.index = index_raw

		#es查询条件
		#聚类发起DNS查询次数超过50次的IP地址
		self.body_aggs = {
		  "query": {
		    "bool": {
		      "must": {
		        "term": {
		          "dst_port": "53",
		#		  "event_name": "DNS查询"
		        }
		      }
		    }
		  },
		  "aggs": {
		    "group_by_src_ip": {
		      "terms": {
		        "field": "src_address",
		        "size": 50,
		        "min_doc_count": 50
		      }
		    }
		  },
		  "size": 0
		}


	#按照IP地址聚类查询域名
	def es_search(self,ip_add):
		self.body = {
		  "query": {
		    "bool": {
		      "must": [
		        {
		          "term": {
	#	            "event_name": "DNS查询"
		            "dst_port": "53"
		          }
		        },
		        {
		          "term": {
		            "src_address": ip_add
		          }
		        }
		      ]
		    }
		  },
		  "aggs": {
		    "group_by_domain_name": {
		      "terms": {
		        "field": "domain_name",
		        "size": 0
		      }
		    }
		  },
		  "size": 1000
		}
		DNS_query = self.es.search(index=self.index, body=self.body ,request_timeout = 3600)
		return DNS_query


	def std(self,array_):#sanity check for NaN
	    if len(array_)>0:
	        return array_.std()
	    else:
	        return 0


	def ave(self,array_):#sanity check for NaN
	    if len(array_)>0:
	        return array_.mean()
	    else:
	        return 0


	def bigrams(self,words):
	    wprev = None
	    for w in words:
	        if not wprev==None:
	            yield (wprev, w)
	        wprev = w


	def trigrams(self,words):
	    wprev1 = None
	    wprev2 = None
	    for w in words:
	        if not (wprev1==None or wprev2==None):
	            yield (wprev1,wprev2, w)
	        wprev1 = wprev2
	        wprev2 = w


	def format(self,_domain):
		_domain_len = []
		_list = _domain.split('.')
		for k in _list:
			_domain_len.append(str(len(k)))
			_format_ = ".".join(_domain_len)
		return _format_


	def pinyin_or_word(self,_string):
	    '''
	    8月3号更新，判断域名是否拼音或拼音首字母组成
	    '''
	    string = _string[1]
	    string = string.split('.')[-2]
	    stringlen = len(string)
	    result = []
	    while True:
	        i_list = []
	        for i in range(1,stringlen+1):
	            print (string[0:i])
	            if string[0:i] in self._list_:
	            	i_list.append(i)
	        print (i_list)
	        if len(i_list) == 0:
	        	print("这是一个英语单词！")
	        	self.resultList.append(_string)
	        	break
	        else:
	        	temp = max(i_list)
	        	result.append(string[0:temp])
	        	string = string.replace(string[0:temp],'')
	        	print ('string',string)
	        	stringlen = len(string)
	        	if stringlen == 0:
	        		print("这是一个拼音！")
	        		break
	def main(self):
		#初始化列表
		self.src_ip_list = []
		self.resultList_dga = []
		self._list_ = []
		self.resultList = []


		#生成数据,提取源IP
		src_ip_aggs = self.es.search(index=self.index, body=self.body_aggs, request_timeout = 3600)
		src_ip_list_buckets = src_ip_aggs['aggregations']['group_by_src_ip']['buckets']

		for _ip in src_ip_list_buckets:
			self.src_ip_list.append(_ip.get('key_as_string'))
		print ("srcip_num = ", len(self.src_ip_list))

		#初始化ngram数据
		n_gram_file = open('n_gram_rank_freq.txt','r')
		gram_rank_dict = dict()
		for i in n_gram_file:
		    cat,gram,freq,rank = i.strip().split(',')
		    gram_rank_dict[gram]=int(rank)
		n_gram_file.close()

		cc = 0

		#生成数据，提取DNS查询事件
		for src_ip in self.src_ip_list:
			print (src_ip)
			DNS_query = self.es_search(src_ip)['aggregations']['group_by_domain_name']['buckets']
			init_DNS_query = []
			domain_doc_count = []
			tup_len_format_list = []
			src_domain_list = []

			for _dns in DNS_query:
				init_DNS_query.append(_dns.get('key'))
				domain_doc_count.append(_dns.get('doc_count'))

			init_DNS_query_count = len(init_DNS_query)
			cc = cc+init_DNS_query_count

			for _key in range(init_DNS_query_count):
				domain_name = init_DNS_query[_key].lower()

				#计算n_gram排名
				bigram = [''.join(i) for i in self.bigrams(domain_name)]
				trigram = [''.join(i) for i in self.trigrams(domain_name)]

				#提取bigram
				bigram_rank = np.array([gram_rank_dict[''.join(i)] if ''.join(i) in gram_rank_dict else 0 for i in self.bigrams(domain_name)])

				#提取trigram
				trigram_rank = np.array([gram_rank_dict[''.join(i)] if ''.join(i) in gram_rank_dict else 0 for i in self.trigrams(domain_name)])

				#随机性熵值
				f_len = float(len(domain_name))
				shannon_count = Counter(i for i in domain_name).most_common()
				entropy = -sum(j/f_len*(math.log(j/f_len)) for i,j in shannon_count)

				#元音字母可读性计算
				model_mat = self.model_data['mat']
				threshold = self.model_data["thresh"]
				git_bool = gib_detect_train.avg_transition_prob(domain_name, model_mat) > threshold

				#域名可信度判断
				if entropy > 2.2 and git_bool == False and (self.ave(bigram_rank) > 250 or self.ave(trigram_rank) > 3000):
					#提取查询次数超过50次的域名
					if domain_doc_count[_key] > 100:
						#域名的长度
						_len = len(domain_name)
						#域名的格式
						_format = self.format(domain_name)
						#域名长度和格式元组
						_tup = (_len,_format)
						tup_len_format_list.append(_tup)
						tup_src_domain = (src_ip , domain_name)
						src_domain_list.append(tup_src_domain)
						test_dga = list(set(src_domain_list))	

			len_tup_len_format_list = len(tup_len_format_list)

			#提取长度和格式相同的域名
			for x in tup_len_format_list:
				c = 0
				initList_dga = []
				y = 0
				while y < len_tup_len_format_list:
					if x == tup_len_format_list[y]:
						c = c + 1
						initList_dga.append(src_domain_list[y])
					if c == 6:
						self.resultList_dga = self.resultList_dga + initList_dga
						break
					y = y + 1


		#列表去重
		self.resultList_dga = list(set(self.resultList_dga))


		#8月3号更新，新增判断域名是否为拼音或拼音首字母组成，匹配则丢弃
		for r_line in open(self.path+'sougou_db.txt','r'):
			r_line = r_line.rstrip("\n")
			self._list_.append(r_line)
		for _string in self.resultList_dga:
			self.pinyin_or_word(_string)

		print ('all=',cc)

		#输出结果
		if len(self.resultList):
			print ("#######################")
			print ('DGA detected!')
			print ("#######################")
			print (self.resultList)
			print ("domain len is:" , len(self.resultList))
			print ("#######################")
		else :
			print ("no DGA detected")


		#8月2号更新：whois查询
		non_whois_count = 0
		whois_count = 0
		error_count = 0
		for _init_whois in self.resultList:
			result = ""
			_whois_domain = _init_whois[1]
			try:
				result = whois.whois(_whois_domain)["domain_name"]
			except whois.parser.PywhoisError:
				print ("PywhoisError")
				error_count = error_count +1
			except KeyError:
				print ("KeyError")
				error_count = error_count +1
			except socket.timeout:
				print ("Timeout")
				error_count = error_count +1
			except ConnectionResetError:
				print ("ConnectionResetError")
				error_count = error_count +1
			except socket.gaierror:
				print ("socket.gaierror")
				error_count = error_count +1
			if result == None or result == "":
				non_whois_count = non_whois_count +1
		#		self.resultList.append(_init_whois)
			else:
				whois_count = whois_count +1
		print ("non-exist whois count is:", non_whois_count)
		print ("error count is:", error_count)
		print ("exist whois count is:", whois_count)
		print ("exist whois percent is:", whois_count/len(self.resultList))

if __name__ == '__main__':
    dga_check = dga_check()
    dga_check.main()


