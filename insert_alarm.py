from datetime import datetime
from elasticsearch import Elasticsearch
import elasticsearch.helpers
import random

es = Elasticsearch( "172.16.100.190:9200" ) 
data = {

"alarm_content": "发现DGA域名。",
"alarm_focus": 0,
"alarm_key": "PJCWV28L0000_110_172.16.104.52_209.244.0.3_0",
"alarm_level": 1,
"alarm_name": "发现DGA域名",
"alarm_stage": 5,
"alarm_tag": [ ],
"alarm_type": "/malware",
"domain_name": "abixolkusz.pl",
"dst_address": "209.244.0.3",
"dst_address_array": [
"209.244.0.3"
],
"dst_address_array_cnt": 1,
"dst_address_str": "209.244.0.3",
"dst_port": 53,
"dst_port_array": [
53
],
"end_time": 1533702888000,
"event_id": [
"423142938978308"
],
"event_ids": "423142938978308",
"id": 453142938978308,
"node_address": "172.16.100.193",
"node_chain": "PJCWV28L0000",
"node_name": "",
"occur_address": "172.16.104.52",
"occur_address_str": "172.16.104.52",
"rule_id": 110,
"rule_type": "普通攻击",
"src_address": "172.16.104.52",
"src_address_array": [
"172.16.104.52"
],
"src_address_array_cnt": 1,
"src_address_str": "172.16.104.52",
"src_port": 33921,
"src_port_array": [
33921
],
"src_port_array_cnt": 1,
"start_time": 1533702886000

}
'''
actions = [
    {
        '_index': "alarm_20180808",  
        '_type': "alarm",
    }
	
]
'''
#elasticsearch.helpers.bulk(es, actions )

es.index( index="alarm_20180808",doc_type="alarm", body=data)





