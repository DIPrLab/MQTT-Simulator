import time
import json
import argparse
import threading
import uuid
import random
import paho.mqtt.client as mqtt
from typing import List
import itertools

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def resolve_topics(cfg: dict) -> List[dict]:
    dims = cfg.get("TOPIC_DIMENSIONS", [])
    interval = int(cfg.get("TIME_INTERVAL", 5))
    # Map dimension names to their values
    dim_map = {}
    for d in dims:
        if "range" in d:
            start, end = d["range"]
            dim_map[d["name"]] = [str(i) for i in range(start, end+1)]
        elif "list" in d:
            dim_map[d["name"]] = [str(x) for x in d["list"]]
        else:
            dim_map[d["name"]] = ["unknown"]

    # Generate topics based on config
    topics = []
    for ttype in cfg.get("TOPIC_TYPES", ["lamp"]):
        dims = cfg.get("TOPIC_TYPE_DIMENSIONS", {}).get(ttype, [])
        combos = itertools.product(*(dim_map[d] for d in reversed(dims) if d in dim_map))
        for combo in combos:
            topic = "/".join(combo)
            if topic:
                topics.append({"topic": topic, "interval": interval, "type": ttype})
            else:
                print(f"[WARN] Skipping empty topic for type '{ttype}' and combo {combo}")
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
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self._running = threading.Event()
        self._running.set()
        self.latencies = []

    def run(self):
        self.client.connect(self.broker_host, self.broker_port, keepalive=60)
        self.client.loop_start()
        try:
            while self._running.is_set():
                time.sleep(1)
        finally:
            self.client.loop_stop()
            self.client.disconnect()

    def on_connect(self, client, userdata, flags, reasonCode, properties=None):
        print(f"[SUB] Connected reasonCode={reasonCode}; subscribing to topics: {self.topics}")
        for topic in self.topics:
            client.subscribe(topic)

    def on_message(self, client, userdata, msg):
        recv_ms = int(time.time() * 1000)
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            ts = payload.get("_timestamp")
            if isinstance(ts, int):
                latency = recv_ms - ts
                self.latencies.append(latency)
                mid = payload.get("_message_id", "-")
                print(f"[SUB] {msg.topic} mid={mid} latency={latency}ms size={len(msg.payload)}")
            else:
                print(f"[SUB] {msg.topic} size={len(msg.payload)} (no timestamp)")
        except Exception:
            print(f"[SUB] {msg.topic} size={len(msg.payload)} (non-JSON)")

    def stop(self):
        self._running.clear()

    def print_latency_stats(self):
        if not self.latencies:
            print("No latency data recorded.")
            return
        print("\n--- Latency Stats ---")
        print(f"Count: {len(self.latencies)}")
        print(f"Min: {min(self.latencies)} ms")
        print(f"Max: {max(self.latencies)} ms")
        print(f"Avg: {sum(self.latencies)/len(self.latencies):.2f} ms")


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

    print(f"Broker: {host}:{port} | Topics: {len(topics)} | Duration: {args.duration or 'infinite'}s")

    pubs: List[Publisher] = []
    for t in topics:
        p = Publisher(host, port, t["topic"], t["interval"], protocol=protocol, qos=args.qos, retain=args.retain)
        p.start()
        pubs.append(p)
        print(f"[PUB] Started -> {t['topic']} every {t['interval']}s")

    sub = None
    if args.with_subscriber:
        subs_cfg = cfg.get("SUBSCRIBERS", {})
        # Use the new structure: TOPICS, USERS, PASSWORDS
        topic_names = subs_cfg.get("TOPICS")
        if not topic_names:
            # fallback to all published topics if not present
            topic_names = [t["topic"] for t in topics]
        # Credentials are available as subs_cfg["USERS"] and subs_cfg["PASSWORDS"]
        # If you want to use credentials, you can pass them to Subscriber or use them for authentication
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
            sub.print_latency_stats()
        # Allow threads to exit cleanly
        time.sleep(1)
        print("Stopped.")


if __name__ == "__main__":
    main()
