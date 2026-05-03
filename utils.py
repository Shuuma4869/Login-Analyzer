import re
import pandas as pd
from datetime import datetime, timedelta

MONTHS = {
    'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
    'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12
}

SSH_FAIL_PAT = re.compile(r"Failed password.*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
SSH_ACCEPT_PAT = re.compile(r"Accepted password.*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
SSH_INVALID_USER = re.compile(r"Invalid user .* from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")
AUTH_FAILURE_GENERIC = re.compile(r"authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)")
ACCESS_LOG_PAT = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+) .+ \".*\" (?P<status>\d{3}) .*")

def try_parse_syslog_timestamp(parts):
    try:
        mon = MONTHS.get(parts[0], None)
        day = int(parts[1])
        time_str = parts[2]
        year = datetime.now().year
        dt = datetime.strptime(f"{year}-{mon}-{day} {time_str}", "%Y-%m-%d %H:%M:%S")
        return dt
    except Exception:
        return None

def parse_log_to_df(raw_text: str) -> pd.DataFrame:
    rows = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        toks = line.split()
        if len(toks) >= 3 and toks[0] in MONTHS:
            ts = try_parse_syslog_timestamp(toks[:3])
        else:
            ts = None

        m = SSH_FAIL_PAT.search(line)
        if m:
            ip = m.group('ip')
            rows.append({'timestamp': ts or datetime.now(), 'ip': ip, 'status': 'FAIL', 'raw': line})
            continue
        m = SSH_INVALID_USER.search(line)
        if m:
            ip = m.group('ip')
            rows.append({'timestamp': ts or datetime.now(), 'ip': ip, 'status': 'FAIL', 'raw': line})
            continue
        m = SSH_ACCEPT_PAT.search(line)
        if m:
            ip = m.group('ip')
            rows.append({'timestamp': ts or datetime.now(), 'ip': ip, 'status': 'SUCCESS', 'raw': line})
            continue
        m = AUTH_FAILURE_GENERIC.search(line)
        if m:
            ip = m.group('ip')
            rows.append({'timestamp': ts or datetime.now(), 'ip': ip, 'status': 'FAIL', 'raw': line})
            continue
        m = ACCESS_LOG_PAT.match(line)
        if m:
            ip = m.group('ip')
            status = int(m.group('status'))
            stat = 'SUCCESS' if 200 <= status < 400 else 'FAIL'
            rows.append({'timestamp': ts or datetime.now(), 'ip': ip, 'status': stat, 'raw': line})
            continue

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)
    return df

def detect_bruteforce_windows(fail_df: pd.DataFrame, window_minutes=5, threshold=10):
    if fail_df.empty:
        return []
    results = []
    grouped = fail_df.groupby('ip')
    window_delta = timedelta(minutes=window_minutes)
    for ip, g in grouped:
        times = list(g['timestamp'].sort_values())
        n = len(times)
        left = 0
        for right in range(n):
            while times[right] - times[left] > window_delta:
                left += 1
            count = right - left + 1
            if count >= threshold:
                results.append({
                    'ip': ip,
                    'window_start': times[left].isoformat(sep=' '),
                    'window_end': times[right].isoformat(sep=' '),
                    'count': count
                })
                break
    return results
