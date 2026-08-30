# Dataset

**File:** `Car_Hacking_5pct.csv`

**Source:** A 5% labeled subset of the HCRL ("Hacking and Countermeasure Research
Lab", Korea University) **Car-Hacking Dataset**, mirrored in the public GitHub
repository:

- https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-CNN-and-Transfer-Learning/blob/main/data/Car_Hacking_5%25.csv
- Full original dataset (much larger): https://ocslab.hksecurity.net/Datasets/car-hacking-dataset

**What it is:** Real CAN-bus traffic logged via the OBD-II port of an actual
vehicle (Hyundai YF Sonata) while real message-injection attacks were
performed against it. It is **not simulated data** — every CAN ID, data
byte, and label in this file comes from the original vehicle capture.

**Columns:**
| Column | Meaning |
|---|---|
| `CAN ID` | Real CAN arbitration ID of the message |
| `DATA[0]`..`DATA[7]` | Real 8-byte CAN payload |
| `Label` | `R` = normal/regular traffic, or one of `DoS`, `Fuzzy`, `gear`, `RPM` (real injected attacks) |

**Note on Timestamp/DLC:** the original raw HCRL capture also includes a
`Timestamp` and `DLC` (data length code) column. This particular 5% CSV
mirror — prepared upstream for an image-based ML pipeline — retains only
CAN ID, the 8 data bytes, and the label, and drops Timestamp/DLC. Message
order in the file still reflects the original capture order, so AutoGuard OS
uses the row sequence as its ordering axis for frequency-style statistics.
No values in the file were fabricated or synthesized.

**Row count:** 818,440 real CAN messages
(701,832 normal / 29,501 DoS / 24,624 Fuzzy / 29,944 gear-spoofing / 32,539 RPM-spoofing)
