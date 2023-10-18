import flask
import threading
import traffic
from flask import jsonify
import os
import configparser


app = flask.Flask("Accounting")
dirname = os.path.dirname(__file__)
config = configparser.RawConfigParser()
config_path = os.path.join(dirname,"./config.ini")
config.read(config_path)
web_port = int(config.get("Web","port"))


@app.route('/', methods=['GET'])
def api():
    all_traffic_till_now = traffic.data
    traffic.data = {}
    new_traffic_list = []
    if bool(all_traffic_till_now):
        for key, value in all_traffic_till_now.items():
            new_traffic_list.append(value)
    
    return jsonify(new_traffic_list)


def start_web_service():
    WebService = threading.Thread(target=run)
    WebService.setDaemon(True)
    WebService.start()

def run():
    app.run(host='0.0.0.0', port=web_port, debug=True, use_reloader=False)