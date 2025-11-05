import json
import argparse
import itertools
import random
import string
from typing import List, Dict

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def escape_sql(s: str) -> str:
    if s is None:
        return ''
    return s.replace("'", "''")

def format_value(val) -> str:
    if val is None:
        return "''"
    return "'{}'".format(escape_sql(str(val)))


def choose_action(policy: dict, cfg: dict) -> str:
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

        # Expand across the configured dimensions named in `expand_on`.
        dims = p.get('expand_on', [])
        # Build list of value-lists for each dimension
        dim_value_lists = []
        for d in dims:
            if d in ('devices', 'device_types'):
                vals = p.get('devices') or ex.get('device_types', []) or []
            else:
                vals = ex.get(d, []) or []
            # if empty, keep an empty-string so product still yields one combo
            if not vals:
                vals = ['']
            dim_value_lists.append(vals)

        # iterate combinations for the requested dimensions
        for combo in itertools.product(*dim_value_lists):
            # build mapping from dimension name -> value and also provide
            mapping = {}
            for name, val in zip(dims, combo):
                mapping[name] = val
            cfg_alias_map = cfg.get('alias_map', {})
            # cfg_alias_map maps expansion key -> list of alias names
            for dname, aliases in cfg_alias_map.items():
                if dname in mapping:
                    for alias in (aliases if isinstance(aliases, (list, tuple)) else [aliases]):
                        mapping[alias] = mapping[dname]
            # ensure dev alias exists
            mapping.setdefault('dev', '')
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
    ex = cfg.get('expansions', {})
    # Helper: get expansion values for an expansion key
    def _vals(key, override=None):
        if override is not None:
            return [override]
        vals = ex.get(key) or []
        return vals if vals else ['']

    # Get device capability mapping from config (attribute -> device types)
    device_map = cfg.get('device_capability_map', {
        # Default fallback for backward compatibility
        'video': ['cam'],
        'alarm': ['proximity'],
        'facilities': ['tstat', 'thermostat']
    })

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

        role = attrs.get('role', '')
        base_priority = cfg.get('role_priorities', {}).get(role, 1)
        
        # Adjust priority by clearance using configured multiplier
        clearance = int(attrs.get('clearance', '#0').replace('#', '') or 0)
        multiplier = cfg.get('clearance_priority_multiplier', 2)
        base_priority += clearance * multiplier

        # Apply role-based restrictions
        role_restrictions = cfg.get('role_restrictions', {})
        restrictions = role_restrictions.get(role, [])
        if restrictions:
            fmt = string.Formatter()
            # load alias map from config (expansion key -> alias or list of aliases)
            cfg_alias_map = cfg.get('alias_map', {})
            for rdef in restrictions:
                t_template = rdef.get('topic_template', '{b}/#')
                action_name = rdef.get('action', 'deny')
                # base offset (can be numeric) plus optional config-provided offset
                priority_offset = int(rdef.get('priority', 0) or 0)
                if 'priority_offset_config' in rdef:
                    try:
                        priority_offset += int(cfg.get(rdef['priority_offset_config'], 0))
                    except Exception:
                        pass

                # find field names used in the template
                fields = [fname for _, fname, _, _ in fmt.parse(t_template) if fname]

                # build the list of expansion keys we should iterate
                expand_keys = []
                for ex_key, aliases in cfg_alias_map.items():
                    # aliases may be a single string or a list/tuple
                    aset = aliases if isinstance(aliases, (list, tuple)) else [aliases]
                    # include ex_key if either its canonical name or any alias appears in template fields
                    if ex_key in fields or any(a in fields for a in aset):
                        expand_keys.append(ex_key)

                # if an explicit floor is provided in the restriction, prefer it
                floor_override = rdef.get('floor')

                # build value lists for each expand key
                dim_value_lists = []
                for key in expand_keys:
                    if key == 'floors' and floor_override is not None:
                        vals = [floor_override]
                    elif key in ('devices', 'device_types'):
                        vals = rdef.get('devices') or ex.get('device_types', []) or []
                    else:
                        vals = ex.get(key, []) or []
                    if not vals:
                        vals = ['']
                    dim_value_lists.append(vals)

                # iterate combinations (or one empty combo if none)
                if not dim_value_lists:
                    combos = [()]
                else:
                    combos = itertools.product(*dim_value_lists)

                for combo in combos:
                    # Build mapping from dimension name -> value
                    mapping = {}
                    for k, v in zip(expand_keys, combo):
                        mapping[k] = v
                            
                    # Apply aliases from config for each expansion key
                    cfg_alias_map = cfg.get('alias_map', {})
                    for dname, aliases in cfg_alias_map.items():
                        if dname in mapping:
                            val = mapping[dname]
                            # Support both single alias string and list of aliases
                            for alias in (aliases if isinstance(aliases, (list, tuple)) else [aliases]):
                                mapping[alias] = val
                                    
                    # Ensure device aliases exist for backward compatibility
                    if 'device_types' in mapping and 'dev' not in mapping:
                        mapping['dev'] = mapping['device_types']
                    if 'devices' in mapping and 'dev' not in mapping:
                        mapping['dev'] = mapping['devices']

                    # optional building filter
                    bval = mapping.get('b', '')
                    if 'building_suffix' in rdef and not str(bval).endswith(rdef['building_suffix']):
                        continue

                    try:
                        topic = t_template.format(**mapping)
                    except Exception:
                        topic = t_template
                    topic = topic.replace('//', '/').strip('/')
                    if topic == '':
                        topic = '#'

                    action = choose_action({'action': action_name}, cfg)
                    rules.append({
                        'topic': topic,
                        'static': f"subj.username=='{username}'",
                        'dynamic': '',
                        'filter': '',
                        'hints': 'subj',
                        'action': action,
                        'priority': base_priority + priority_offset
                    })
        else:
            # Backwards-compatible fallback: original intern-specific rules if no config provided
            if role == 'intern':
                buildings = _vals('buildings')
                for b in buildings:
                    if not b:
                        continue
                    if str(b).endswith('2'):
                        topic = f"{b}/#"
                        action = choose_action({'action': 'deny'}, cfg)
                        rules.append({
                            'topic': topic,
                            'static': f"subj.username=='{username}'",
                            'dynamic': '',
                            'filter': '',
                            'hints': 'subj',
                            'action': action,
                            'priority': base_priority + cfg.get('security_restriction_bonus', 5)
                        })
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
                # Get expansion keys that have values in the config, excluding device-related keys
                spatial_keys = [k for k in ex.keys() if k not in ('devices', 'device_types')]
                if not spatial_keys:
                    spatial_keys = []
                for dev in devs:
                    # build dim value lists
                    dim_value_lists = []
                    for key in spatial_keys:
                        dim_value_lists.append(_vals(key))
                    if dim_value_lists:
                        combos = itertools.product(*dim_value_lists)
                    else:
                        combos = [()]
                    for combo in combos:
                        mapping = {}
                        for k, v in zip(spatial_keys, combo):
                            mapping[k] = v
                        # Apply aliases from config for each expansion key
                        cfg_alias_map = cfg.get('alias_map', {})
                        for dname, aliases in cfg_alias_map.items():
                            if dname in mapping:
                                val = mapping[dname]
                                # Support both single alias string and list of aliases
                                for alias in (aliases if isinstance(aliases, (list, tuple)) else [aliases]):
                                    mapping[alias] = val
                        
                        # Ensure dev alias exists for backward compatibility
                        mapping['dev'] = dev
                        try:
                            topic = "{b}/{fl}/{r}/{dev}/#".format(**mapping)
                        except Exception:
                            # fall back to manual join
                            parts = [mapping.get('b', ''), mapping.get('fl', ''), mapping.get('r', ''), dev]
                            topic = '/'.join([p for p in parts if p]) + '/#'
                        topic = topic.replace('//', '/').strip('/')
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
                            'priority': base_priority
                        })

        # Create an attribute-based generic rule for each capability
        for aname, aval in attrs.items():
            if isinstance(aval, str) and aval.startswith('?') and 'true' in aval:
                devs = device_map.get(aname, [])
                # Get expansion keys that have values in the config
                spatial_keys = [k for k in ex.keys() if k not in ('devices', 'device_types')]
                
                for dev in devs:
                    dim_value_lists = []
                    for key in spatial_keys:
                        dim_value_lists.append(_vals(key))
                    if dim_value_lists:
                        combos = itertools.product(*dim_value_lists)
                    else:
                        combos = [()]
                    
                    for combo in combos:
                        # Build mapping from dimension name -> value
                        mapping = {}
                        for k, v in zip(spatial_keys, combo):
                            mapping[k] = v
                            
                        # Apply aliases from config for each expansion key
                        cfg_alias_map = cfg.get('alias_map', {})
                        for dname, aliases in cfg_alias_map.items():
                            if dname in mapping:
                                val = mapping[dname]
                                # Support both single alias string and list of aliases
                                for alias in (aliases if isinstance(aliases, (list, tuple)) else [aliases]):
                                    mapping[alias] = val
                                    
                        # Ensure dev alias exists
                        mapping['dev'] = dev
                        try:
                            topic = "{b}/{fl}/{r}/{dev}/#".format(**mapping)
                        except Exception:
                            parts = [mapping.get('b', ''), mapping.get('fl', ''), mapping.get('r', ''), dev]
                            topic = '/'.join([p for p in parts if p]) + '/#'
                        topic = topic.replace('//', '/').strip('/')
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

        f.write('insert into rules (topic, static, dynamic, filter, hints, action, priority) values\n')
        f.write(',\n'.join(insert_rows) + ';\n')

def main():
    parser = argparse.ArgumentParser(description='Generate ABAC policy SQL from base policy templates')
    parser.add_argument('--config', default='policy_settings.json', help='Path to policy_settings.json')
    parser.add_argument('--out', default='generated_policies.sql', help='Output SQL script path')
    parser.add_argument('--max-policies', type=int, help='Maximum number of policies to generate (overrides config)')
    parser.add_argument('--seed', type=int, help='Optional deterministic random seed (overrides config)')
    args = parser.parse_args()

    cfg = load_config(args.config)
    # deterministic seed support: CLI overrides config
    seed = args.seed if args.seed is not None else cfg.get('seed')
    if seed is not None:
        try:
            seed = int(seed)
            random.seed(seed)
        except Exception:
            pass
    rules = expand_base_policies(cfg)
    # generate per-user and per-attribute dynamic rules
    user_rules = generate_user_attribute_rules(cfg)
    rules.extend(user_rules)
    # Deduplicate rules by (topic, static, dynamic, priority), resolving action conflicts by configured weights.
    def _pick_action_weighted(candidates):
        probs = cfg.get('action_probabilities', {}) or {}
        # build weights in same order as candidates
        weights = []
        total = 0.0
        for a in candidates:
            try:
                w = float(probs.get(a, 0) or 0)
            except Exception:
                w = 0.0
            weights.append(w)
            total += w
        if total <= 0:
            return random.choice(candidates)
        return random.choices(candidates, weights=weights, k=1)[0]

    # Aggregate rules by (topic, static, dynamic, priority) and count actions.
    grouped = {}
    for r in rules:
        key = (r.get('topic'), r.get('static'), r.get('dynamic'), r.get('priority'))
        g = grouped.get(key)
        if g is None:
            # store representative rule and action counts
            grouped[key] = {
                'rep': r.copy(),
                'action_counts': { (r.get('action') or 'deny').lower(): 1 }
            }
            continue

        # increment action count
        act = (r.get('action') or 'deny').lower()
        counts = g['action_counts']
        counts[act] = counts.get(act, 0) + 1

        # keep the representative rule as the one with highest numeric priority
        if r.get('priority', 0) > g['rep'].get('priority', 0):
            g['rep'] = r.copy()

    # finalize unique rules by selecting the action with the highest count; on tie prefer grant
    uniq = []
    for key, data in grouped.items():
        rep = data['rep']
        counts = data['action_counts']
        max_count = max(counts.values())
        candidates = [a for a, c in counts.items() if c == max_count]
        rep['action'] = _pick_action_weighted(candidates) if candidates else (rep.get('action') or 'deny')
        uniq.append(rep)

    # Apply max policies limit with generalization
    max_policies = args.max_policies or cfg.get('max_policies', 1000)
    if max_policies > 0 and len(uniq) > max_policies:
        print(f'Generalizing and limiting output to {max_policies} policies (from {len(uniq)} total)')
        
        # Group rules by their core characteristics
        by_pattern = {}
        for rule in uniq:
            topic = rule['topic']
            static = rule['static']
            action = rule['action']
            priority = rule['priority']
            
            # Extract pattern components
            parts = topic.split('/')
            if len(parts) >= 4:
                # Create more general patterns based on specificity needed
                building = parts[0]
                floor = parts[1]
                
                # Normalize topic parts and handle device type
                if '#' in parts[-1]:
                    device_part = parts[-1].split('#')[0].strip('/')
                    suffix = '#'
                else:
                    device_part = parts[-1]
                    suffix = ''
                
                # Generate increasingly general patterns
                patterns = [
                    (f"{building}/{floor}/+/{device_part}{suffix}", 3),
                    (f"{building}/+/+/{device_part}{suffix}", 2),
                    (f"+/+/+/{device_part}{suffix}", 1),
                    ("#", 0)
                ]
                
                # Use the most specific pattern that helps us meet our limit
                for pattern, specificity in patterns:
                    # use priority in the key, but not action, so we can resolve
                    key = (pattern, static, priority)
                    if key not in by_pattern:
                        by_pattern[key] = {
                            'rule': {
                                'topic': pattern,
                                'static': static,
                                'dynamic': rule.get('dynamic', ''),
                                'filter': rule.get('filter', ''),
                                'hints': rule.get('hints', ''),
                                'action': action,
                                'priority': priority
                            },
                            'specificity': specificity,
                            'count': 1,
                            'action_counts': { (action or 'deny').lower(): 1 }
                        }
                    else:
                        # increment count and track action counts (majority decides)
                        by_pattern[key]['count'] += 1
                        ac = by_pattern[key].setdefault('action_counts', {})
                        ac[action.lower()] = ac.get(action.lower(), 0) + 1
                        # prefer representative rule with higher priority
                        if priority > by_pattern[key]['rule'].get('priority', 0):
                            by_pattern[key]['rule'] = {
                                'topic': pattern,
                                'static': static,
                                'dynamic': rule.get('dynamic', ''),
                                'filter': rule.get('filter', ''),
                                'hints': rule.get('hints', ''),
                                'action': action,
                                'priority': priority
                            }
            else:
                # resolve action conflicts if multiple appear for same key
                key = (topic, static, priority)
                if key not in by_pattern:
                    by_pattern[key] = {
                        'rule': rule,
                        'specificity': 4,  # Higher specificity for unique patterns
                        'count': 1,
                        'action_counts': { (action or 'deny').lower(): 1 }
                    }
                else:
                    by_pattern[key]['count'] += 1
                    ac = by_pattern[key].setdefault('action_counts', {})
                    ac[action.lower()] = ac.get(action.lower(), 0) + 1
                    # prefer representative if this has higher priority
                    if priority > by_pattern[key]['rule'].get('priority', 0):
                        by_pattern[key]['rule'] = rule
        
        # Generalization config
        gen_cfg = cfg.get('generalization', {})
        grouping_key = gen_cfg.get('grouping_key', 'static')
        distribution = gen_cfg.get('distribution_strategy', 'proportional')

        # Create groups based on configured grouping_key
        for _k, _entry in list(by_pattern.items()):
                ac = _entry.get('action_counts', {})
                if ac:
                    maxc = max(ac.values())
                    cands = [a for a, c in ac.items() if c == maxc]
                    _entry['rule']['action'] = _pick_action_weighted(cands) if cands else _entry['rule'].get('action')

        groups = {}
        for item in by_pattern.values():
            rule = item['rule']
            if grouping_key == 'static':
                grp_key = rule.get('static') or rule.get('hints') or '#'
            elif grouping_key == 'hints':
                grp_key = rule.get('hints') or rule.get('static') or '#'
            elif grouping_key == 'device':
                # extract device part from topic if present
                t = rule.get('topic', '')
                parts = t.split('/')
                if parts:
                    # device is usually the 4th segment in expanded topics, otherwise use last
                    grp_key = parts[3] if len(parts) > 3 else parts[-1]
                else:
                    grp_key = '#'
            else:
                grp_key = rule.get('static') or rule.get('hints') or '#'

            groups.setdefault(str(grp_key), []).append(item)

        # Sort items within each group by priority, specificity, and count
        for g in groups.values():
            g.sort(key=lambda x: (-x['rule']['priority'], -x['specificity'], -x['count']))

        # Distribution strategies
        selected = []
        import collections

        if distribution == 'round_robin':
            # Order groups by total priority so important groups are served earlier
            group_order = sorted(groups.keys(), key=lambda k: -sum(i['rule']['priority'] for i in groups[k]))
            queue = collections.deque(group_order)
            while queue and len(selected) < max_policies:
                key = queue.popleft()
                bucket = groups.get(key)
                if not bucket:
                    continue
                item = bucket.pop(0)
                selected.append(item['rule'])
                if bucket:
                    queue.append(key)

        elif distribution == 'proportional':
            # Allocate slots proportional to group sizes (at least 1 if present)
            total_count = sum(sum(i['count'] for i in groups[k]) for k in groups)
            # fallback if total_count is 0
            if total_count <= 0:
                total_count = sum(len(groups[k]) for k in groups)
            alloc = {}
            for k in groups:
                group_size = sum(i['count'] for i in groups[k])
                share = 0
                if total_count > 0:
                    share = max(1, int(round((group_size / total_count) * max_policies)))
                alloc[k] = share

            # select per group based on allocated share
            for k, share in alloc.items():
                bucket = groups.get(k, [])
                take = min(len(bucket), share)
                for _ in range(take):
                    if len(selected) >= max_policies:
                        break
                    selected.append(bucket.pop(0)['rule'])

            # if not enough selected, fill by highest priority remaining
            remaining = []
            for k in groups:
                remaining.extend(groups[k])
            remaining.sort(key=lambda x: (-x['rule']['priority'], -x['specificity'], -x['count']))
            i = 0
            while len(selected) < max_policies and i < len(remaining):
                selected.append(remaining[i]['rule'])
                i += 1

        elif distribution == 'priority_buckets':
            # Select items from highest priority down, but try to distribute across groups within a priority
            # Build priority -> group -> items mapping
            prio_map = {}
            for k, bucket in groups.items():
                for it in bucket:
                    p = it['rule'].get('priority', 0)
                    prio_map.setdefault(p, {}).setdefault(k, []).append(it)

            for p in sorted(prio_map.keys(), reverse=True):
                # within this priority, round-robin across groups
                grp_keys = list(prio_map[p].keys())
                q = collections.deque(grp_keys)
                while q and len(selected) < max_policies:
                    gk = q.popleft()
                    bucket = prio_map[p].get(gk)
                    if not bucket:
                        continue
                    it = bucket.pop(0)
                    selected.append(it['rule'])
                    if bucket:
                        q.append(gk)
                if len(selected) >= max_policies:
                    break

        else:
            # default fallback: previous behavior - take highest priority across all
            all_items = []
            for bucket in groups.values():
                all_items.extend(bucket)
            all_items.sort(key=lambda x: (-x['rule']['priority'], -x['specificity'], -x['count']))
            for it in all_items[:max_policies]:
                selected.append(it['rule'])

        uniq = selected

    # If after deduplication/generalization we still have fewer than the
    # requested max_policies, refill from the original grouped entries
    max_policies = args.max_policies or cfg.get('max_policies', 1000)
    if max_policies > 0 and len(uniq) < max_policies:
        need = max_policies - len(uniq)
        # track existing final keys including action so we don't add exact duplicates
        existing_keys = set((r.get('topic'), r.get('static'), r.get('dynamic'), r.get('priority'), r.get('action')) for r in uniq)

        # build candidate list from grouped originals: (count, candidate_rule)
        candidates = []
        for g in grouped.values():
            rep = g.get('rep', {})
            for a, cnt in g.get('action_counts', {}).items():
                key = (rep.get('topic'), rep.get('static'), rep.get('dynamic'), rep.get('priority'), a)
                if key in existing_keys:
                    continue
                cand = rep.copy()
                cand['action'] = a
                candidates.append((cnt, cand))

        # prefer candidates with higher original counts and higher priority
        candidates.sort(key=lambda x: (-x[0], -x[1].get('priority', 0)))

        for cnt, cand in candidates:
            if len(uniq) >= max_policies:
                break
            k = (cand.get('topic'), cand.get('static'), cand.get('dynamic'), cand.get('priority'), cand.get('action'))
            if k in existing_keys:
                continue
            uniq.append(cand)
            existing_keys.add(k)

    write_sql(cfg, uniq, args.out)
    print(f'Wrote {len(uniq)} rules to {args.out}')

if __name__ == '__main__':
    main()
