
## High-Level Simulation Algorithm Process

1. **Configuration Loading**
	- Loads simulation parameters and topic structure from `settings.json`.
	- Defines topic dimensions, types, and data schemas for message generation.

2. **Topic Generation**
	- Dynamically generates all possible MQTT topics based on configured dimensions and types.
	- Ensures coverage for all combinations described in the config.

3. **Publisher Initialization**
	- Creates a publisher thread for each topic.
	- Each publisher generates and publishes every possible value for its topic, as described by the data schema.
	- Messages include metadata such as message ID and timestamp.

4. **Subscriber Initialization (Optional)**
	- If enabled, starts a subscriber thread that subscribes to a configurable set of topics.
	- Subscriber records message latency and prints statistics.

5. **Simulation Execution**
	- Publishers and subscribers run concurrently for the configured duration (or indefinitely).
	- All threads are stopped gracefully at the end of the simulation.

## Running the Simulator

To run execute:
python simulator.py --config "settings.json" --with-subscriber --publishers-per-topic 3 --subscribers-per-topic 2 --duration 30