import json
import argparse
import itertools
import random
from typing import List, Dict

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def escape_sql(s: str) -> str:
    if s is None:
        return ''
    return s.replace("'", "''")

def format_value(val) -> str:
    # Wrap and escape strings for SQL literal
    if val is None:
        return "''"
    return "'{}'".format(escape_sql(str(val)))


def choose_action(policy: dict, cfg: dict) -> str:
    """Choose an action ('grant'|'deny'|'filter') based on policy-level or global probabilities."""
    probs = policy.get('action_probabilities') or cfg.get('action_probabilities') or {}
    if not probs:
        return policy.get('action', 'deny')
    items = []
    total = 0.0
    for k, v in probs.items():
        try:
            vv = float(v)
        except Exception:
            vv = 0.0
        if vv <= 0:
            continue
        items.append((k, vv))
        total += vv
    if not items:
        return policy.get('action', 'deny')
    r = random.random() * total
    cum = 0.0
    for k, vv in items:
        cum += vv
        if r <= cum:
            return k
    return items[-1][0]

def expand_base_policies(cfg: dict) -> List[dict]:
    ex = cfg.get('expansions', {})
    bp = cfg.get('base_policies', [])
    rules = []
    for p in bp:
        # determine dimensions to expand
        devices = p.get('devices', [])
        # if devices empty, use placeholder None to keep template intact
        dev_list = devices if devices else [None]

        build_list = ex.get('buildings', [""])
        floor_list = ex.get('floors', [""])
        room_list = ex.get('rooms', [""])

        # helper: choose action will be resolved at module-level

        # if expand_on empty: emit template as-is
        if not p.get('expand_on'):
            topic = p['topic_template']
            # support range expansion at template level
            prange = p.get('range')
            if prange:
                rmin = int(prange.get('min', 0))
                rmax = int(prange.get('max', 0))
                step = int(prange.get('step', 1)) or 1
                for v in range(rmin, rmax + 1, step):
                    # allow using v_plus placeholder
                    v_plus = v + 1
                    static = p.get('static', '')
                    dynamic = p.get('dynamic', '')
                    flt = p.get('filter', '')
                    try:
                        static = static.format(v=v, v_plus=v_plus)
                        dynamic = dynamic.format(v=v, v_plus=v_plus)
                        flt = flt.format(v=v, v_plus=v_plus)
                    except Exception:
                        pass
                    action = choose_action(p, cfg)
                    rules.append({
                        'topic': topic,
                        'static': static,
                        'dynamic': dynamic,
                        'filter': flt,
                        'hints': p.get('hints', ''),
                        'action': action,
                        'priority': int(p.get('priority', 0))
                    })
            else:
                action = choose_action(p, cfg)
                rules.append({
                    'topic': topic,
                    'static': p.get('static', ''),
                    'dynamic': p.get('dynamic', ''),
                    'filter': p.get('filter', ''),
                    'hints': p.get('hints', ''),
                    'action': action,
                    'priority': int(p.get('priority', 0))
                })
            continue

        # Expand across specified dimensions
        for b, fl, r, dev in itertools.product(build_list, floor_list, room_list, dev_list):
            # create mapping
            mapping = {'b': b, 'fl': fl, 'r': r, 'dev': dev or ''}
            try:
                topic = p['topic_template'].format(**mapping)
            except Exception:
                # fallback to template literal if format fails
                topic = p['topic_template']
            # normalize double slashes
            topic = topic.replace('//', '/')
            # strip trailing slashes
            topic = topic.strip('/')
            if topic == '':
                topic = '#'

            # if a range is defined for this base policy, expand values and substitute
            prange = p.get('range')
            if prange:
                rmin = int(prange.get('min', 0))
                rmax = int(prange.get('max', 0))
                step = int(prange.get('step', 1)) or 1
                for v in range(rmin, rmax + 1, step):
                    v_plus = v + 1
                    static = p.get('static', '')
                    dynamic = p.get('dynamic', '')
                    flt = p.get('filter', '')
                    try:
                        static = static.format(v=v, v_plus=v_plus)
                        dynamic = dynamic.format(v=v, v_plus=v_plus)
                        flt = flt.format(v=v, v_plus=v_plus)
                    except Exception:
                        pass
                    action = choose_action(p, cfg)
                    rules.append({
                        'topic': topic,
                        'static': static,
                        'dynamic': dynamic,
                        'filter': flt,
                        'hints': p.get('hints', ''),
                        'action': action,
                        'priority': int(p.get('priority', 0))
                    })
            else:
                action = choose_action(p, cfg)
                rules.append({
                    'topic': topic,
                    'static': p.get('static', ''),
                    'dynamic': p.get('dynamic', ''),
                    'filter': p.get('filter', ''),
                    'hints': p.get('hints', ''),
                    'action': action,
                    'priority': int(p.get('priority', 0))
                })
    return rules


def generate_user_attribute_rules(cfg: dict) -> List[dict]:
    """Generate allow/deny rules per user based on their attributes.

    Produces rules that:
    - Grant access to device topics when a user has the matching attribute (e.g. video -> cam)
    - Deny access to sensitive buildings/areas for interns
    - Emit per-user static rules (subj.username == ...) so tests can target individual users
    """
    ex = cfg.get('expansions', {})
    build_list = ex.get('buildings', [""])
    floor_list = ex.get('floors', [""])
    room_list = ex.get('rooms', [""])

    # device mapping: attribute -> device types
    device_map = {
        'video': ['cam'],
        'alarm': ['proximity'],
        'facilities': ['tstat', 'thermostat']
    }

    # build userid -> username map
    uid_to_user = {}
    for u in cfg.get('users', []):
        uid_to_user[u.get('userid')] = u.get('username')

    # collect attributes per user
    user_attrs = {}
    for uid, name, val in cfg.get('user_attributes', []):
        user_attrs.setdefault(uid, {})[name] = val

    rules = []

    for uid, attrs in user_attrs.items():
        username = uid_to_user.get(uid)
        if not username:
            continue

        # interns denied to some places (example rules)
        role = attrs.get('role', '')
        if role == 'intern':
            # deny interns to building2 entirely and to high security floors
            for b in build_list:
                if not b:
                    continue
                # bldg2 in particular
                if b.endswith('2'):
                    topic = f"{b}/#"
                    action = choose_action({'action': 'deny'}, cfg)
                    rules.append({
                        'topic': topic,
                        'static': f"subj.username=='{username}'",
                        'dynamic': '',
                        'filter': '',
                        'hints': 'subj',
                        'action': action,
                        'priority': 1
                    })
                # deny interns from third-floor camera areas
                topic = f"{b}/f3/#"
                action = choose_action({'action': 'deny'}, cfg)
                rules.append({
                    'topic': topic,
                    'static': f"subj.username=='{username}'",
                    'dynamic': '',
                    'filter': '',
                    'hints': 'subj',
                    'action': action,
                    'priority': 1
                })

        # For each attribute that maps to devices, grant per-user access to those device topics
        for aname, aval in attrs.items():
            # match ?true attributes (capabilities)
            if isinstance(aval, str) and aval.startswith('?') and 'true' in aval:
                devs = device_map.get(aname, [])
                for dev in devs:
                    for b, fl, r in itertools.product(build_list, floor_list, room_list):
                        mapping = {'b': b, 'fl': fl, 'r': r, 'dev': dev}
                        topic = f"{b}/{fl}/{r}/{dev}/#".replace('//', '/').strip('/')
                        if topic == '':
                            topic = '#'
                        action = choose_action({'action': 'grant'}, cfg)
                        rules.append({
                            'topic': topic,
                            'static': f"subj.username=='{username}'",
                            'dynamic': '',
                            'filter': '',
                            'hints': 'subj',
                            'action': action,
                            'priority': 5
                        })

        # Additionally, create an attribute-based generic rule for each capability
        for aname, aval in attrs.items():
            if isinstance(aval, str) and aval.startswith('?') and 'true' in aval:
                devs = device_map.get(aname, [])
                for dev in devs:
                    for b, fl, r in itertools.product(build_list, floor_list, room_list):
                        topic = f"{b}/{fl}/{r}/{dev}/#".replace('//', '/').strip('/')
                        if topic == '':
                            topic = '#'
                        action = choose_action({'action': 'grant'}, cfg)
                        rules.append({
                            'topic': topic,
                            'static': f"subj.{aname} ?? false",
                            'dynamic': '',
                            'filter': '',
                            'hints': 'subj',
                            'action': action,
                            'priority': 5
                        })

    return rules

def write_sql(cfg: dict, rules: List[dict], out_path: str):
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('create database if not exists peaauth;\n')
        f.write('use peaauth;\n\n')

        f.write('create table users (\n')
        f.write('\tuserid\tint auto_increment primary key,\n')
        f.write("\tclientid \tvarchar(64),\n")
        f.write("\tusername\tvarchar(64),\n")
        f.write("\tpassword\tvarchar(64)\n")
        f.write(');\n\n')

        f.write('create table user_attributes (\n')
        f.write('\tuserid\tint,\n')
        f.write('\tname\tvarchar(64),\n')
        f.write('\tval\tvarchar(255),\n')
        f.write('\tforeign key (userid) references users(userid) on delete cascade\n')
        f.write(');\n\n')

        # users
        f.write('-- users from settings\n')
        f.write('insert into users (userid, clientid, username, password) values\n')
        users = cfg.get('users', [])
        rows = []
        for u in users:
            uid = u.get('userid')
            clientid = u.get('clientid', '')
            username = u.get('username', '')
            password = u.get('password', '')
            rows.append('({uid}, {client}, {user}, {pw})'.format(
                uid=uid,
                client=format_value(clientid),
                user=format_value(username),
                pw=format_value(password)
            ))
        f.write(',\n'.join(rows) + ';\n\n')

        # attributes
        f.write('-- user attributes from settings\n')
        f.write('insert into user_attributes (userid, name, val) values\n')
        attrs = cfg.get('user_attributes', [])
        attr_rows = []
        for a in attrs:
            uid, name, val = a
            attr_rows.append('({uid}, {name}, {val})'.format(
                uid=uid, name=format_value(name), val=format_value(val)
            ))
        f.write(',\n'.join(attr_rows) + ';\n\n')

        # rules table
        f.write('create table rules (\n')
        f.write('\truleid int auto_increment primary key,\n')
        f.write('\ttopic varchar(1024),\n')
        f.write('\tstatic varchar(4096),\n')
        f.write('\tdynamic varchar(4096),\n')
        f.write('\tfilter varchar(4096),\n')
        f.write("\thints set('subj','obj','ctx','payload','json','dsubj'),\n")
        f.write("\taction enum('filter', 'grant', 'deny'),\n")
        f.write('\tpriority int\n')
        f.write(');\n\n')

        f.write('-- generated rules\n')
        if not rules:
            f.write('-- (no rules generated)\n')
            return

        insert_rows = []
        for r in rules:
            topic = format_value(r.get('topic', '#'))
            static = format_value(r.get('static', ''))
            dynamic = format_value(r.get('dynamic', ''))
            flt = format_value(r.get('filter', ''))
            hints = format_value(r.get('hints', ''))
            action = format_value(r.get('action', 'deny'))
            prio = int(r.get('priority', 0))
            insert_rows.append('({topic}, {static}, {dynamic}, {filter}, {hints}, {action}, {prio})'.format(
                topic=topic, static=static, dynamic=dynamic, filter=flt, hints=hints, action=action, prio=prio
            ))

        # SQL requires matching columns - we will explicitly list columns to match values order
        f.write('insert into rules (topic, static, dynamic, filter, hints, action, priority) values\n')
        f.write(',\n'.join(insert_rows) + ';\n')

def main():
    parser = argparse.ArgumentParser(description='Generate ABAC policy SQL from base policy templates')
    parser.add_argument('--config', default='policy_settings.json', help='Path to policy_settings.json')
    parser.add_argument('--out', default='generated_policies.sql', help='Output SQL script path')
    args = parser.parse_args()

    cfg = load_config(args.config)
    rules = expand_base_policies(cfg)
    # generate per-user and per-attribute dynamic rules
    user_rules = generate_user_attribute_rules(cfg)
    rules.extend(user_rules)

    # deduplicate similar rules (topic + static + dynamic + action + priority)
    seen = set()
    uniq = []
    for r in rules:
        key = (r['topic'], r['static'], r['dynamic'], r['action'], r['priority'])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    write_sql(cfg, uniq, args.out)
    print(f'Wrote {len(uniq)} rules to {args.out}')

if __name__ == '__main__':
    main()
