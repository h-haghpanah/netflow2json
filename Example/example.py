from netflow2json.analyser import NetflowProcessor

processor = NetflowProcessor(web_port=8080, netflow_port=2055, local_ip_ranges=['172.16.11.0/24','172.16.12.0/24','172.16.13.0/24','172.16.14.0/24','192.168.0.0/24','192.168.1.0/24'])
processor.start()