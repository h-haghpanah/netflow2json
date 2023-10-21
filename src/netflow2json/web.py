import flask
import threading
from . import traffic
from flask import jsonify

app = flask.Flask("Accounting")


@app.route('/', methods=['GET'])
def api():
    all_traffic_till_now = traffic.data
    traffic.data = {}
    new_traffic_list = []
    if bool(all_traffic_till_now):
        for key, value in all_traffic_till_now.items():
            new_traffic_list.append(value)
    
    return jsonify(new_traffic_list)


def start_web_service(port):
    WebService = threading.Thread(target=run, args=(port,))
    WebService.setDaemon(True)
    WebService.start()

def run(port):
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)