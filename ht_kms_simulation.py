"""
HT-KMS: Hierarchical Trust-Based Key Management Scheme
IoT Security Simulation — 500+ Devices
"""

import random
import hashlib
import time
import os
from datetime import datetime
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────
NUM_DEVICES         = 500
NUM_EDGE_NODES      = 5          # 100 devices per edge node
SIM_ROUNDS          = 50         # each round = one trust evaluation cycle
MALICIOUS_RATIO     = 0.10       # 10% devices start as compromised
SYBIL_RATIO         = 0.05       # 5% devices are Sybil attackers

TRUST_RENEW_THRESH  = 0.60       # below this → early key renewal
TRUST_REVOKE_THRESH = 0.40       # below this for 3 consecutive rounds → revoke
REVOKE_CONSECUTIVE  = 3          # how many bad rounds before full revocation

WEIGHTS = {"CR": 0.30, "PF": 0.35, "IH": 0.20, "EU": 0.15}

LOG_FILE = "ht_kms_log.txt"
PLOT_FILE = "ht_kms_results.png"

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def generate_key(device_id: str, edge_id: int, round_num: int) -> str:
    raw = f"{device_id}-{edge_id}-{round_num}-{time.time_ns()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()

def clamp(val, lo=0.0, hi=1.0):
    return max(lo, min(hi, val))

# ─────────────────────────────────────────────
#  DEVICE
# ─────────────────────────────────────────────
class Device:
    def __init__(self, device_id: str, edge_id: int, device_type: str = "normal"):
        self.device_id   = device_id
        self.edge_id     = edge_id
        self.device_type = device_type   # normal | malicious | sybil

        # Keys
        self.session_key      = generate_key(device_id, edge_id, 0)
        self.key_version      = 1
        self.key_renewals     = 0
        self.key_revocations  = 0

        # Trust
        self.trust_score      = round(random.uniform(0.75, 0.95), 3)
        self.trust_history    = [self.trust_score]
        self.below_revoke_streak = 0
        self.status           = "active"   # active | warned | revoked | reregistered

        # Behavior params (malicious devices degrade faster)
        self._degrade_rate = {
            "normal":    0.01,
            "malicious": 0.06,
            "sybil":     0.04,
        }[device_type]

    def compute_trust(self) -> float:
        """Simulate the 4-factor trust formula."""
        if self.status == "revoked":
            return 0.0

        base = self.trust_score

        # Each factor: normal devices fluctuate slightly, bad devices degrade
        noise = random.gauss(0, 0.02)

        CR = clamp(base + noise - self._degrade_rate * random.uniform(0.5, 1.5))
        PF = clamp(base + noise - self._degrade_rate * random.uniform(0.3, 1.2))
        IH = clamp(np.mean(self.trust_history[-5:]) if self.trust_history else base)
        EU = clamp(base + random.gauss(0, 0.03) - self._degrade_rate * 0.5)

        score = (
            WEIGHTS["CR"] * CR +
            WEIGHTS["PF"] * PF +
            WEIGHTS["IH"] * IH +
            WEIGHTS["EU"] * EU
        )
        return round(clamp(score), 4)

    def update_trust(self, new_score: float):
        self.trust_score = new_score
        self.trust_history.append(new_score)

    def reregister(self, edge_id: int, round_num: int):
        """Device kicked out and rejoins fresh."""
        self.session_key          = generate_key(self.device_id, edge_id, round_num)
        self.key_version         += 1
        self.trust_score          = round(random.uniform(0.50, 0.70), 3)
        self.below_revoke_streak  = 0
        self.status               = "reregistered"
        self.key_revocations     += 1

# ─────────────────────────────────────────────
#  EDGE NODE
# ─────────────────────────────────────────────
class EdgeNode:
    def __init__(self, edge_id: int, devices: list):
        self.edge_id    = edge_id
        self.devices    = devices
        self.key_store  = {d.device_id: d.session_key for d in devices}

    def evaluate_and_act(self, round_num: int, logger) -> dict:
        stats = {"renewals": 0, "revocations": 0, "normal": 0}

        for device in self.devices:
            if device.status == "revoked":
                continue

            new_score = device.compute_trust()
            device.update_trust(new_score)

            # ── REVOCATION CHECK ──────────────────────────────
            if new_score < TRUST_REVOKE_THRESH:
                device.below_revoke_streak += 1
            else:
                device.below_revoke_streak = 0

            if device.below_revoke_streak >= REVOKE_CONSECUTIVE:
                old_key = device.session_key
                device.reregister(self.edge_id, round_num)
                self.key_store[device.device_id] = device.session_key
                stats["revocations"] += 1
                logger.log(round_num, device, "REVOKED",
                           f"Score={new_score:.3f} | OldKey={old_key} → NewKey={device.session_key}")

            # ── RENEWAL CHECK ─────────────────────────────────
            elif new_score < TRUST_RENEW_THRESH:
                device.status   = "warned"
                old_key         = device.session_key
                device.session_key = generate_key(device.device_id, self.edge_id, round_num)
                device.key_version += 1
                device.key_renewals += 1
                self.key_store[device.device_id] = device.session_key
                stats["renewals"] += 1
                logger.log(round_num, device, "RENEWED",
                           f"Score={new_score:.3f} | OldKey={old_key} → NewKey={device.session_key}")

            # ── ALL GOOD ──────────────────────────────────────
            else:
                device.status = "active"
                stats["normal"] += 1

        return stats

# ─────────────────────────────────────────────
#  CLOUD
# ─────────────────────────────────────────────
class Cloud:
    def __init__(self):
        self.registry     = {}   # device_id → public info
        self.trust_log    = defaultdict(list)

    def register(self, device: Device):
        self.registry[device.device_id] = {
            "edge_id": device.edge_id,
            "type":    device.device_type,
            "joined":  datetime.now().isoformat()
        }

    def sync(self, devices: list):
        for d in devices:
            self.trust_log[d.device_id].append(d.trust_score)

# ─────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────
class Logger:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.entries  = []
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"HT-KMS Simulation Log — {datetime.now()}\n")
            f.write("=" * 80 + "\n\n")

    def log(self, round_num: int, device: Device, event: str, detail: str):
        line = (f"[Round {round_num:02d}] [{event:<8}] "
                f"Device={device.device_id} | Type={device.device_type:<9} | "
                f"Edge={device.edge_id} | {detail}")
        self.entries.append(line)
        print(line)
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def section(self, title: str):
        line = f"\n{'─'*80}\n  {title}\n{'─'*80}"
        print(line)
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")

# ─────────────────────────────────────────────
#  SIMULATION
# ─────────────────────────────────────────────
class Simulation:
    def __init__(self):
        self.logger = Logger(LOG_FILE)
        self.cloud  = Cloud()

        # Create devices
        all_devices = []
        for i in range(NUM_DEVICES):
            edge_id = i // (NUM_DEVICES // NUM_EDGE_NODES)
            if i < int(NUM_DEVICES * SYBIL_RATIO):
                dtype = "sybil"
            elif i < int(NUM_DEVICES * (SYBIL_RATIO + MALICIOUS_RATIO)):
                dtype = "malicious"
            else:
                dtype = "normal"
            d = Device(f"DEV-{i:04d}", edge_id, dtype)
            self.cloud.register(d)
            all_devices.append(d)

        # Create edge nodes
        self.edge_nodes = []
        for eid in range(NUM_EDGE_NODES):
            assigned = [d for d in all_devices if d.edge_id == eid]
            self.edge_nodes.append(EdgeNode(eid, assigned))

        self.all_devices = all_devices

        # Tracking for plots
        self.round_stats = []   # per round aggregates
        self.sample_trust = defaultdict(list)  # trust over time for sample devices

        # Pick sample devices to plot individually
        self.samples = {
            "normal":    next(d for d in all_devices if d.device_type == "normal"),
            "malicious": next(d for d in all_devices if d.device_type == "malicious"),
            "sybil":     next(d for d in all_devices if d.device_type == "sybil"),
        }

    def run(self):
        self.logger.section(f"SIMULATION START — {NUM_DEVICES} devices, {SIM_ROUNDS} rounds")
        print(f"\n{'='*60}")
        print(f"  HT-KMS Simulation")
        print(f"  Devices: {NUM_DEVICES}  |  Edge Nodes: {NUM_EDGE_NODES}  |  Rounds: {SIM_ROUNDS}")
        print(f"  Malicious: {int(NUM_DEVICES*MALICIOUS_RATIO)}  |  Sybil: {int(NUM_DEVICES*SYBIL_RATIO)}")
        print(f"{'='*60}\n")

        total_renewals    = 0
        total_revocations = 0

        for r in range(1, SIM_ROUNDS + 1):
            self.logger.section(f"ROUND {r}")
            r_renewals = r_revocations = r_normal = 0

            for en in self.edge_nodes:
                stats = en.evaluate_and_act(r, self.logger)
                r_renewals    += stats["renewals"]
                r_revocations += stats["revocations"]
                r_normal      += stats["normal"]

            self.cloud.sync(self.all_devices)

            total_renewals    += r_renewals
            total_revocations += r_revocations

            # Aggregate trust by type
            scores = {"normal": [], "malicious": [], "sybil": []}
            for d in self.all_devices:
                scores[d.device_type].append(d.trust_score)

            avg = {k: round(np.mean(v), 4) if v else 0 for k, v in scores.items()}

            self.round_stats.append({
                "round":       r,
                "renewals":    r_renewals,
                "revocations": r_revocations,
                "normal_count": r_normal,
                "avg_trust_normal":    avg["normal"],
                "avg_trust_malicious": avg["malicious"],
                "avg_trust_sybil":     avg["sybil"],
            })

            for label, device in self.samples.items():
                self.sample_trust[label].append(device.trust_score)

            print(f"\n  Round {r:02d} Summary → "
                  f"Renewals: {r_renewals} | Revocations: {r_revocations} | "
                  f"Avg Trust [Normal={avg['normal']} | "
                  f"Malicious={avg['malicious']} | Sybil={avg['sybil']}]")

        # Final summary
        self.logger.section("FINAL SUMMARY")
        active   = sum(1 for d in self.all_devices if d.status in ("active","warned","reregistered"))
        revoked  = sum(1 for d in self.all_devices if d.status == "revoked")
        detected = sum(1 for d in self.all_devices
                       if d.device_type in ("malicious","sybil") and d.key_revocations > 0)
        total_bad = int(NUM_DEVICES * (MALICIOUS_RATIO + SYBIL_RATIO))
        detection_rate = round(detected / total_bad * 100, 1) if total_bad else 0

        summary = f"""
  Total Rounds          : {SIM_ROUNDS}
  Total Devices         : {NUM_DEVICES}
  Total Key Renewals    : {total_renewals}
  Total Key Revocations : {total_revocations}
  Active Devices        : {active}
  Detection Rate        : {detection_rate}% of malicious/sybil nodes revoked
        """
        print(summary)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(summary)

        self.plot()
        print(f"\n  Log saved  → {LOG_FILE}")
        print(f"  Plot saved → {PLOT_FILE}\n")

    # ─────────────────────────────────────────
    #  PLOTTING
    # ─────────────────────────────────────────
    def plot(self):
        rounds = [s["round"] for s in self.round_stats]
        fig = plt.figure(figsize=(18, 14), facecolor="#0f1117")
        fig.suptitle("HT-KMS Simulation Results", fontsize=20,
                     color="white", fontweight="bold", y=0.98)

        gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.45, wspace=0.35)

        style = {
            "axes.facecolor":   "#1a1d2e",
            "axes.edgecolor":   "#444",
            "axes.labelcolor":  "#ccc",
            "xtick.color":      "#aaa",
            "ytick.color":      "#aaa",
            "grid.color":       "#2a2d3e",
            "grid.linestyle":   "--",
            "grid.alpha":       0.6,
        }
        plt.rcParams.update(style)

        # ── 1. Average Trust Score Over Time ─────────────────
        ax1 = fig.add_subplot(gs[0, 0])
        ax1.plot(rounds, [s["avg_trust_normal"]    for s in self.round_stats],
                 color="#4fc3f7", linewidth=2, label="Normal")
        ax1.plot(rounds, [s["avg_trust_malicious"] for s in self.round_stats],
                 color="#ef5350", linewidth=2, label="Malicious")
        ax1.plot(rounds, [s["avg_trust_sybil"]     for s in self.round_stats],
                 color="#ffb74d", linewidth=2, label="Sybil")
        ax1.axhline(TRUST_REVOKE_THRESH, color="#ff1744", linestyle=":", linewidth=1.5, label="Revoke threshold (0.4)")
        ax1.axhline(TRUST_RENEW_THRESH,  color="#ffd600", linestyle=":", linewidth=1.5, label="Renew threshold (0.6)")
        ax1.set_title("Avg Trust Score by Device Type", color="white", fontsize=12)
        ax1.set_xlabel("Round"); ax1.set_ylabel("Trust Score")
        ax1.legend(fontsize=8, facecolor="#1a1d2e", labelcolor="white")
        ax1.grid(True); ax1.set_ylim(0, 1)

        # ── 2. Key Renewals & Revocations Per Round ───────────
        ax2 = fig.add_subplot(gs[0, 1])
        bar_w = 0.4
        x = np.array(rounds)
        ax2.bar(x - bar_w/2, [s["renewals"]    for s in self.round_stats],
                bar_w, color="#4db6ac", label="Renewals", alpha=0.85)
        ax2.bar(x + bar_w/2, [s["revocations"] for s in self.round_stats],
                bar_w, color="#ef5350", label="Revocations", alpha=0.85)
        ax2.set_title("Key Events Per Round", color="white", fontsize=12)
        ax2.set_xlabel("Round"); ax2.set_ylabel("Count")
        ax2.legend(fontsize=8, facecolor="#1a1d2e", labelcolor="white")
        ax2.grid(True, axis="y")

        # ── 3. Sample Device Trust Trajectories ──────────────
        ax3 = fig.add_subplot(gs[1, 0])
        colors = {"normal": "#4fc3f7", "malicious": "#ef5350", "sybil": "#ffb74d"}
        for label, scores in self.sample_trust.items():
            ax3.plot(rounds[:len(scores)], scores,
                     color=colors[label], linewidth=2, label=f"{label.capitalize()} device")
        ax3.axhline(TRUST_REVOKE_THRESH, color="#ff1744", linestyle=":", linewidth=1.5)
        ax3.axhline(TRUST_RENEW_THRESH,  color="#ffd600", linestyle=":", linewidth=1.5)
        ax3.set_title("Sample Device Trust Over Time", color="white", fontsize=12)
        ax3.set_xlabel("Round"); ax3.set_ylabel("Trust Score")
        ax3.legend(fontsize=8, facecolor="#1a1d2e", labelcolor="white")
        ax3.grid(True); ax3.set_ylim(0, 1)

        # ── 4. Cumulative Revocations ─────────────────────────
        ax4 = fig.add_subplot(gs[1, 1])
        cumrev = np.cumsum([s["revocations"] for s in self.round_stats])
        ax4.fill_between(rounds, cumrev, alpha=0.3, color="#ef5350")
        ax4.plot(rounds, cumrev, color="#ef5350", linewidth=2)
        ax4.set_title("Cumulative Key Revocations", color="white", fontsize=12)
        ax4.set_xlabel("Round"); ax4.set_ylabel("Total Revocations")
        ax4.grid(True)

        # ── 5. Device Status Pie ──────────────────────────────
        ax5 = fig.add_subplot(gs[2, 0])
        status_counts = defaultdict(int)
        for d in self.all_devices:
            status_counts[d.status] += 1
        labels = list(status_counts.keys())
        sizes  = list(status_counts.values())
        pie_colors = {"active": "#4fc3f7", "warned": "#ffb74d",
                      "revoked": "#ef5350", "reregistered": "#81c784"}
        clrs = [pie_colors.get(l, "#aaa") for l in labels]
        ax5.pie(sizes, labels=labels, colors=clrs, autopct="%1.1f%%",
                textprops={"color": "white", "fontsize": 10},
                wedgeprops={"edgecolor": "#0f1117", "linewidth": 2})
        ax5.set_title("Final Device Status Distribution", color="white", fontsize=12)

        # ── 6. Trust Score Distribution (Final Round) ─────────
        ax6 = fig.add_subplot(gs[2, 1])
        for dtype, color in colors.items():
            vals = [d.trust_score for d in self.all_devices if d.device_type == dtype]
            if vals:
                ax6.hist(vals, bins=20, alpha=0.6, color=color,
                         label=dtype.capitalize(), edgecolor="#0f1117")
        ax6.axvline(TRUST_REVOKE_THRESH, color="#ff1744", linestyle=":", linewidth=2)
        ax6.axvline(TRUST_RENEW_THRESH,  color="#ffd600", linestyle=":", linewidth=2)
        ax6.set_title("Final Trust Score Distribution", color="white", fontsize=12)
        ax6.set_xlabel("Trust Score"); ax6.set_ylabel("Device Count")
        ax6.legend(fontsize=8, facecolor="#1a1d2e", labelcolor="white")
        ax6.grid(True, axis="y")

        plt.savefig(PLOT_FILE, dpi=150, bbox_inches="tight", facecolor="#0f1117")
        plt.close()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    sim = Simulation()
    sim.run()