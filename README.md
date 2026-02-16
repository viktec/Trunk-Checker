# Trunk Checker

A comprehensive tool for verifying SIP Trunks, designed to validate registration status, configuration correctness, and perform active call testing.

## Features

- **Interactive Configuration**: Prompts for Main Trunk Number, Authentication ID, Password, and SIP Registrar Address.
- **Registration Verification**: detailed checks on registration status and sip negotiation.
- **Call Testing**: 
  - Inbound Call Test
  - Outbound Call Test
- **Deep Analysis**:
  - Source & Transport validation
  - Detailed SIP Message logging
  - RFC Compliance checks
  - PRACK, Session Timer, P-Preferred Identity
  - RTCP & SRTP analysis
  - Codec negotiation specifics

## Getting Started

### Prerequisites

- Python 3.8+
- `dnspython` library

### Installation

```bash
git clone https://github.com/viktec/Trunk-Checker.git
cd Trunk-Checker
pip install dnspython
```

## Usage

Run the main script and follow the interactive prompts:

```bash
python main.py
```

### Workflow
1.  **Configuration**: Enter your Main Trunk Number, Auth ID, Password, and Registrar Domain.
2.  **DNS Analysis**: The tool automatically checks for NAPTR and SRV records to determine the correct transport (UDP/TCP/TLS) and target IP.
3.  **Registration**: Tries to register with the SIP provider using Digest Authentication.
4.  **Inbound Call Test**: (Optional) Listens for an incoming call to verify route headers and codecs.
5.  **Outbound Call Test**: (Optional) Initiates a call to a destination number to verify authorization and early media.
6.  **Final Report**: Generates a 3CX-style checklist report covering:
    *   RFC Compliance (Standard headers)
    *   Feature Support (PRACK, Session Timers, 100rel)
    *   Security (SRTP, Identity Headers)
    *   Codecs Negotiation (G711, G729, Opus, etc.)

## Project Structure

- `agents/`: logic modules (Registration, DNS, Inbound/Outbound calls, Analysis).
- `core/`: Low-level SIP transport and message parsing.
- `utils/`: Logging helpers.
- `docs/agents/`: Detailed architecture documentation (local only).

## License

Distributed under the MIT License. See `LICENSE` for more information.
