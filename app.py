from flask import Flask, render_template, request, jsonify, Response
import threading
import uuid
import time
import json
import queue
from scanner import Scanner
from db import GraphDB

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cge_secret'

try:
    db = GraphDB(uri="bolt://localhost:7687", user="neo4j", password="password")
    print("[+] Connected to Neo4j")
except:
    db = None
    print("[!] Neo4j not available")

tasks = {}
task_announcers = {}

class MessageAnnouncer:
    def __init__(self):
        self.listeners = []
        self.lock = threading.Lock()

    def listen(self):
        q = queue.Queue(maxsize=100)
        with self.lock:
            self.listeners.append(q)
        return q

    def announce(self, msg):
        with self.lock:
            self.listeners = [q for q in self.listeners if not q.full()]
            for q in self.listeners:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    pass

def format_sse(data: str, event=None) -> str:
    msg = f'data: {data}\n\n'
    if event is not None:
        msg = f'event: {event}\n{msg}'
    return msg

def run_scanner_task(task_id, domain, cookies):
    announcer = task_announcers.get(task_id)

    def progress_callback(data):
        if 'updates' not in tasks[task_id]:
            tasks[task_id]['updates'] = []
        tasks[task_id]['updates'].append(data)
        if len(tasks[task_id]['updates']) > 100:
            tasks[task_id]['updates'] = tasks[task_id]['updates'][-100:]

        if announcer:
            try:
                announcer.announce(format_sse(json.dumps(data), event='update'))
            except Exception as e:
                print(f"SSE announce error: {e}")

    scanner = Scanner(domain, cookies=cookies, cli_mode=False, callback=progress_callback, db=db, scan_id=task_id)
    result = scanner.scan()
    tasks[task_id]['status'] = 'completed'
    tasks[task_id]['result'] = result

    if announcer:
        try:
            announcer.announce(format_sse(json.dumps({'type': 'completed', 'result': result}), event='completed'))
        except:
            pass

    if db:
        try:
            db.save_scan(task_id, domain, result['nodes'], result['edges'], result['endpoints'], result['requests'])
        except Exception as e:
            print(f"DB save error: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    domain = data.get('domain')
    cookies = data.get('cookies', '')
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    task_id = str(uuid.uuid4())
    tasks[task_id] = {'status': 'running', 'updates': []}
    task_announcers[task_id] = MessageAnnouncer()
    thread = threading.Thread(target=run_scanner_task, args=(task_id, domain, cookies))
    thread.daemon = True
    thread.start()
    return jsonify({'task_id': task_id})

@app.route('/scan_status/<task_id>')
def scan_status(task_id):
    if task_id not in tasks:
        return jsonify({'error': 'Task not found'}), 404
    task = tasks[task_id]
    if task['status'] == 'completed':
        return jsonify({'status': 'completed', 'result': task['result']})
    else:
        updates = task.get('updates', [])
        return jsonify({'status': 'running', 'updates': updates})

@app.route('/scan_stream/<task_id>')
def scan_stream(task_id):
    if task_id not in tasks:
        return jsonify({'error': 'Task not found'}), 404

    def event_stream():
        announcer = task_announcers.get(task_id)
        if not announcer:
            return

        messages = announcer.listen()
        task = tasks[task_id]
        if task['status'] == 'completed':
            yield format_sse(json.dumps({'type': 'completed', 'result': task['result']}), event='completed')
            return

        while True:
            try:
                msg = messages.get(timeout=15)
                yield msg
            except queue.Empty:
                yield format_sse(json.dumps({'type': 'heartbeat'}), event='heartbeat')
            except Exception:
                break

    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/save_current', methods=['POST'])
def save_current():
    if not db:
        return jsonify({'error': 'Neo4j not available'}), 500

    data = request.get_json()
    domain = data.get('domain', 'unknown')
    nodes = data.get('nodes', [])
    edges = data.get('edges', [])
    endpoints = data.get('endpoints', {})
    requests_data = data.get('requests', [])

    scan_id = str(uuid.uuid4())

    try:
        db.save_scan(scan_id, domain, nodes, edges, endpoints, requests_data)
        return jsonify({'scan_id': scan_id, 'status': 'saved'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/load_scan/<scan_id>')
def load_scan(scan_id):
    if not db:
        return jsonify({'error': 'Neo4j not available'}), 500
    data = db.load_scan(scan_id)
    if data:
        return jsonify(data)
    return jsonify({'error': 'Not found'}), 404

@app.route('/list_scans')
def list_scans():
    if not db:
        return jsonify([])
    return jsonify(db.list_scans())

if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)
