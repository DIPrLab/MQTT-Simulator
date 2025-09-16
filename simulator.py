"""
Simple MQTT traffic simulator (publisher + optional subscriber).

Features:
- Reads minimal config from settings.json (BROKER_URL, BROKER_PORT, TOPICS[*].PREFIX, TIME_INTERVAL)
- Publishes random JSON payloads to each topic at the specified interval
- Adds metadata fields: _message_id, _timestamp
- Optional subscriber that logs received messages and basic latency if timestamp present

Usage:
  python simple_simulator.py --config settings.json --with-subscriber --duration 60

Dependencies:
  pip install paho-mqtt
"""

import argparse
import json
import os
import random
import threading
import time
import uuid
from typing import List

import paho.mqtt.client as mqtt


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_topics(cfg: dict) -> List[dict]:
    topics_cfg = cfg.get("TOPICS", [])
    topics: List[dict] = []
    for t in topics_cfg:
        t_type = t.get("TYPE", "single")
        prefix = t.get("PREFIX", "topic")
        interval = int(t.get("TIME_INTERVAL", 5))

        if t_type == "multiple":
            start = int(t.get("RANGE_START", 1))
            end = int(t.get("RANGE_END", 1))
            for i in range(start, end + 1):
                topics.append({"topic": f"{prefix}/{i}", "interval": interval})
        elif t_type == "list":
            for name in t.get("LIST", []):
                topics.append({"topic": f"{prefix}/{name}", "interval": interval})
        else:  # single
            topics.append({"topic": prefix, "interval": interval})
    return topics


def mqtt_protocol_from_int(protocol_int: int):
    # Map int to paho constants (4 -> v3.1.1, 5 -> v5)
    if protocol_int == 5:
        return mqtt.MQTTv5
    return mqtt.MQTTv311


class Publisher(threading.Thread):
    def __init__(self, broker_host: str, broker_port: int, topic: str, interval: int, protocol: int, qos: int = 0, retain: bool = False):
        super().__init__(daemon=True)
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.topic = topic
        self.interval = max(1, int(interval))
        self.qos = int(qos)
        self.retain = bool(retain)
        self._running = threading.Event()
        self._running.set()
        self.client = mqtt.Client(client_id=f"pub-{topic}-{uuid.uuid4().hex[:8]}", protocol=mqtt_protocol_from_int(protocol))

    def run(self):
        self.client.connect(self.broker_host, self.broker_port, keepalive=60)
        self.client.loop_start()
        try:
            while self._running.is_set():
                payload = {
                    "value": random.random(),
                    "_message_id": str(uuid.uuid4()),
                    # milliseconds since epoch
                    "_timestamp": int(time.time() * 1000),
                }
                payload_str = json.dumps(payload)
                self.client.publish(self.topic, payload_str, qos=self.qos, retain=self.retain)
                time.sleep(self.interval)
        finally:
            self.client.loop_stop()
            self.client.disconnect()

    def stop(self):
        self._running.clear()



class Subscriber(threading.Thread):
    def __init__(self, broker_host: str, broker_port: int, topics: List[str], protocol: int):
        super().__init__(daemon=True)
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.topics = topics
        self.client = mqtt.Client(client_id=f"sub-{uuid.uuid4().hex[:8]}", protocol=mqtt_protocol_from_int(protocol))
        self._running = threading.Event()
        self._running.set()

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[SUB] Connected rc={rc}; subscribing to topics: {self.topics}")
        for topic in self.topics:
            client.subscribe(topic)

    def on_message(self, client, userdata, msg):
        recv_ms = int(time.time() * 1000)
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            ts = payload.get("_timestamp")
            latency = f" latency={recv_ms - ts}ms" if isinstance(ts, int) else ""
            mid = payload.get("_message_id", "-")
            print(f"[SUB] {msg.topic} mid={mid}{latency} size={len(msg.payload)}")
        except Exception:
            print(f"[SUB] {msg.topic} size={len(msg.payload)} (non-JSON)")

    def run(self):
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.connect(self.broker_host, self.broker_port, keepalive=60)
        self.client.loop_start()
        try:
            while self._running.is_set():
                time.sleep(0.2)
        finally:
            self.client.loop_stop()
            self.client.disconnect()

    def stop(self):
        self._running.clear()


def main():
    parser = argparse.ArgumentParser(description="Simple MQTT traffic simulator")
    parser.add_argument("--config", default="settings.json", help="Path to settings.json")
    parser.add_argument("--with-subscriber", action="store_true", help="Start a subscriber for all published topics")
    parser.add_argument("--duration", type=int, default=30, help="How long to run in seconds (0 = run forever)")
    parser.add_argument("--qos", type=int, default=0, choices=[0,1,2], help="QoS for publishes")
    parser.add_argument("--retain", action="store_true", help="Publish messages with retain flag")
    args = parser.parse_args()

    cfg = load_config(args.config)
    # Prefer settings.json, fallback to a public test broker to avoid connection-refused errors
    host = cfg.get("BROKER_URL") or "test.mosquitto.org"
    port = int(cfg.get("BROKER_PORT", 1883))
    protocol = int(cfg.get("PROTOCOL_VERSION", 4))

    topics = resolve_topics(cfg)
    if not topics:
        print("No topics configured in settings.json -> TOPICS. Exiting.")
        return

    print(f"Broker: {host}:{port} | Topics: {len(topics)} | Duration: {args.duration or 'infinite'}s")

    pubs: List[Publisher] = []
    for t in topics:
        p = Publisher(host, port, t["topic"], t["interval"], protocol=protocol, qos=args.qos, retain=args.retain)
        p.start()
        pubs.append(p)
        print(f"[PUB] Started -> {t['topic']} every {t['interval']}s")

    sub = None
    if args.with_subscriber:
        # Subscribe only to the exact topics being published
        topic_names = [t["topic"] for t in topics]
        sub = Subscriber(host, port, topic_names, protocol=protocol)
        sub.start()

    try:
        if args.duration and args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for p in pubs:
            p.stop()
        if sub:
            sub.stop()
        # Allow threads to exit cleanly
        time.sleep(1)
        print("Stopped.")


if __name__ == "__main__":
    main()
