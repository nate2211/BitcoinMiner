<img width="1273" height="737" alt="bitcoinminer" src="https://github.com/user-attachments/assets/aefb7471-be47-43f2-893a-f8a93f1a54f0" />

# ₿ BitcoinMiner

A high-performance Bitcoin mining framework featuring hybrid CPU acceleration, VirtualASIC integration, and advanced batch hashing pipelines.

Designed for experimentation, optimization, and high-throughput SHA-256d mining using both software and hardware-accelerated techniques.

---

## 🚀 Features

### ⚡ High Performance Hashing
- Optimized SHA-256d hashing pipeline  
- VirtualASIC acceleration support  
- Batch hashing for increased throughput  
- Hybrid CPU execution model  

### 🧠 VirtualASIC Integration
- Native VirtualASIC DLL support  
- Kernel-based hashing execution  
- Candidate merge optimization  
- Dynamic core utilization  

### 🔀 Dual-Lane CPU Support
- Parallel CPU hashing lanes  
- Enhanced throughput without DLL modification  
- Load-balanced hashing pipeline  
- Scalable thread configuration  

### 🧮 Advanced Work Processing
- Efficient nonce generation and distribution  
- Batch candidate processing  
- Reduced redundant computations  
- Optimized work scheduling  

### 🔗 Mining Backend Support
- Stratum protocol compatibility  
- Pool mining support  
- Flexible job handling  
- Low-latency submission pipeline  

### 📊 Monitoring & Metrics
- Real-time hashrate tracking  
- Accepted/rejected share stats  
- Worker status reporting  
- Debug and performance logs  

---

## 🏗️ Architecture Overview

```
        ┌────────────────────┐
        │   Stratum Server   │
        │   (Mining Pool)    │
        └─────────┬──────────┘
                  │
                  ▼
        ┌────────────────────┐
        │ Job Manager        │
        └─────────┬──────────┘
                  │
                  ▼
        ┌──────────────────────────┐
        │ Work Generator           │
        │ (Nonce Distribution)     │
        └─────────┬────────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
┌──────────────┐   ┌──────────────┐
│ CPU Lane 1   │   │ CPU Lane 2   │
│ (Hashing)    │   │ (Hashing)    │
└──────┬───────┘   └──────┬───────┘
       │                  │
       ▼                  ▼
        ┌──────────────────────────┐
        │ VirtualASIC Engine       │
        │ (Kernel Execution)       │
        └─────────┬────────────────┘
                  ▼
        ┌──────────────────────────┐
        │ Share Validation         │
        └─────────┬────────────────┘
                  ▼
        ┌──────────────────────────┐
        │ Share Submission         │
        └──────────────────────────┘
```

---

## 📦 Project Structure

```
bitcoinminer/
├── miner_core.py        # Main mining pipeline
├── btc_virtualasic.py   # VirtualASIC integration
├── btc_stratum.py       # Stratum protocol client
├── btc_models.py        # Data models (jobs, shares)
├── btc_native.py        # Native bridge / DLL interaction
├── config.py            # Configuration
├── utils/               # Utilities
└── logs/                # Runtime logs
```

---

## ⚙️ Installation

### Requirements
- Python 3.10+  
- Windows (recommended)  
- VirtualASIC DLL  
- OpenCL (optional, depending on setup)  

### Setup

```bash
git clone https://github.com/nate2211/bitcoinminer.git
cd bitcoinminer

pip install -r requirements.txt
```

---

## 🔧 Configuration

Example configuration:

```python
POOL_URL = "stratum+tcp://127.0.0.1:3333"
WALLET = "YOUR_BTC_WALLET"
WORKER_NAME = "worker1"

THREADS = 8
ENABLE_DUAL_LANE = True

VIRTUAL_ASIC_DLL = "VirtualASIC.dll"
ENABLE_VIRTUAL_ASIC = True
```

---

## ▶️ Running the Miner

```bash
python miner_core.py
```

---

## ⚡ Performance Tuning

### CPU Optimization
- Increase `THREADS` for higher throughput  
- Enable dual-lane mode for parallel hashing  

### VirtualASIC Optimization
- Ensure DLL is properly loaded  
- Tune kernel parameters if available  
- Monitor CPU/GPU utilization  

### General Tips
- Keep system cooled properly  
- Avoid CPU throttling  
- Balance workload between lanes  

---

## 🧠 Advanced Features

### 🔀 Dual-Lane CPU Execution
Runs multiple hashing lanes simultaneously for improved performance.

### ⚡ Batch Hashing Pipeline
Processes multiple nonces at once to maximize efficiency.

### 🧮 Candidate Merge Optimization
Combines multiple hashing results to reduce overhead.

### 🔗 Flexible Backend Integration
Supports multiple pool configurations and job formats.

---

## 📊 Performance Notes

- Best performance achieved with VirtualASIC enabled  
- Dual-lane CPU significantly improves throughput  
- Batch processing reduces overhead per hash  

---

## ⚠️ Disclaimer

This project is for **educational and experimental purposes**.  
Mining Bitcoin may require significant computational resources and electricity.

---

## 📄 License

MIT License

---

## 👤 Author

**Nathan Andrew McDonald**  
GitHub: https://github.com/nate2211

---

## ⭐ Contributing

Pull requests are welcome.  
For major changes, open an issue first to discuss what you'd like to change.
