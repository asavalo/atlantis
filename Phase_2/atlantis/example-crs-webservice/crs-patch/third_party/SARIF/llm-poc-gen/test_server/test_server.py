import json
import sys
from pathlib import Path
from queue import Queue

from flask import Flask, jsonify

app = Flask(__name__)
msg: Queue[dict] = Queue()


@app.route("/", methods=["GET"])
def root():
    while msg.qsize() > 0:
        return jsonify(msg.get())
    return jsonify({"command": "quit"})


if __name__ == "__main__":
    try:
        with Path(sys.argv[1]).open("rt") as f:
            r = json.load(f)
            for response in r:
                print(f"[I] Insert Response: {response}")
                msg.put(response)
    except Exception:
        print(f"[E] Invalid format: {sys.argv[1]}")
    app.run(port=10100)
