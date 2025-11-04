
# MQTT Simulator

This project contains two simulators:

1. A message simulator for MQTT traffic generation
2. A policy simulator for generating ABAC (Attribute-Based Access Control) policies

## Message Simulator

### Message Simulation Process

1. **Configuration Loading**
   - Loads simulation parameters and topic structure from `message_settings.json`
   - Defines topic dimensions, types, and data schemas for message generation

2. **Topic Generation**
   - Dynamically generates all possible MQTT topics based on configured dimensions and types
   - Ensures coverage for all combinations described in the config

3. **Publisher Initialization**
   - Creates a publisher thread for each topic
   - Each publisher generates and publishes every possible value for its topic
   - Messages include metadata such as message ID and timestamp

4. **Subscriber Initialization (Optional)**
   - If enabled, starts a subscriber thread that subscribes to a configurable set of topics
   - Subscriber records message latency and prints statistics

5. **Simulation Execution**
   - Publishers and subscribers run concurrently for the configured duration
   - All threads are stopped gracefully at the end of the simulation

### Running the Message Simulator

```bash
python message_simulator.py --config "message_settings.json" --with-subscriber --publishers-per-topic 3 --subscribers-per-topic 2 --duration 30
```

Parameters:

- `--config`: Path to message settings JSON file
- `--with-subscriber`: Enable subscriber mode
- `--publishers-per-topic`: Number of concurrent publishers per topic
- `--subscribers-per-topic`: Number of concurrent subscribers per topic
- `--duration`: Simulation duration in seconds (0 for infinite)
- `--qos`: MQTT QoS level (0, 1, or 2)
- `--retain`: Set retain flag on messages

## Policy Simulator

### Policy Generation Process

1. **Configuration Loading**
   - Loads policy configuration from `policy_settings.json`
   - Includes users, attributes, and base policy templates
   - Defines role priorities and action probabilities

2. **Policy Generation**
   - Expands base policy templates across configured dimensions:
     - Buildings
     - Floors
     - Rooms
     - Device types
   - Generates user and attribute-specific rules
   - Applies role-based priorities and clearance levels

3. **Policy Optimization**
   - Deduplicates redundant rules
   - Generalizes specific rules when policy count exceeds limit
   - Prioritizes rules based on:
     - Priority level
     - Role importance
     - Security restrictions

4. **SQL Generation**
   - Creates MySQL/MariaDB compatible SQL script
   - Includes database schema for:
     - Users
     - User attributes
     - Access control rules
   - Generates INSERT statements for all entities

### Running the Policy Simulator

```bash
python policy_simulator.py --config "policy_settings.json" --out "generated_policies.sql" --max-policies 500
```

Parameters:

- `--config`: Path to policy settings JSON file
- `--out`: Output SQL file path
- `--max-policies`: Maximum number of policies to generate (overrides config)
 - `--seed`: Optional deterministic random seed. If provided, the generator will be deterministic. The CLI seed overrides a `seed` value in the config file.

Configuration notes (policy_settings.json):

- `role_restrictions` (object): map role -> list of restriction definitions. Each restriction supports:
   - `topic_template`: topic template with placeholders like `{b}` and `{fl}` (e.g. "{b}/f3/#")
   - `building_suffix`: optional string to filter which buildings the restriction applies to (e.g. "2" to match building names ending with "2")
   - `floor`: optional explicit floor value to substitute for `{fl}`
   - `action`: `deny` or `grant` (used when creating the restriction rule)
   - `priority`: numeric priority offset for the rule
   - `priority_offset_config`: optional key name in the config whose numeric value will be added to the rule priority (e.g. `security_restriction_bonus`)

- `generalization` (object): controls how many and which rules are kept when the generator hits the `max_policies` limit:
   - `grouping_key`: `static` | `hints` | `device` — how to group rules before distributing slots
   - `distribution_strategy`: `round_robin` | `proportional` | `priority_buckets` — how selected slots are allocated among groups

These fields let you tune which role-based restrictions are created and how rules are generalized when truncation is required.

## Configuration Files

### message_settings.json

- Broker connection settings
- Topic structure and dimensions
- Data schemas for different message types
- Publisher and subscriber settings

### policy_settings.json

- User definitions and attributes
- Building/floor/room dimensions
- Role priorities and clearance levels
- Base policy templates
- Action probabilities
- Policy generation limits