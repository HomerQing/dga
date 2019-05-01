from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch( "172.16.100.190:9200" ) 
data = {
"alarm_content": "发现DGA域名。",
"alarm_count": 1,
"alarm_focus": 0,
"alarm_key": "PJCWV28L0000_110_172.16.104.52_209.244.0.3_0",
"alarm_level": 1,
"alarm_name": "发现DGA域名",
"alarm_stage": 5,
"alarm_status": 0,
"alarm_tag": [ ],
"alarm_type": "/malware",
"cep_rule_id": 110,
"end_time": 1533702888000,
"id": 60547898688888,
"node_address": "172.16.100.193",
"node_chain": "PJCWV28L0000",
"node_name": "",
"occur_address": "172.16.104.52",
"occur_address_str": "172.16.104.52",
"src_address": "172.16.104.52",
"src_address_str": "172.16.104.52",
"start_time": 1533702886000
}

es.index( index="alarm_merge_20180808",doc_type="alarm_merge", body=data)