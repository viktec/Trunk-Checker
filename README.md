# Trunk Checker

A comprehensive tool for verifying SIP Trunks, designed to validate registration status, configuration correctness, and perform active call testing.

## Features

- **Interactive Configuration**: Prompts for Main Trunk Number, Authentication ID, Password, and SIP Registrar Address.
- **NethVoice Proxy Support**: Automated injection and testing for Kamailio/FreePBX environments with zero-touch config.
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
6.  **Final Report**: Generates checklist report covering:
    *   RFC Compliance (Standard headers)
    *   Feature Support (PRACK, Session Timers, 100rel)
    *   Security (SRTP, Identity Headers)
    *   Codecs Negotiation (G711, G729, Opus, etc.)

## NethVoice/Kamailio Integration

The tool includes a specialized **NethVoice Proxy Test** mode (Option 2) designed for complex proxy environments.

### Key Features
- **Zero-Touch Configuration**:
  - **Auto-detects Outbound Proxy**: Scans existing PJSIP config to find the correct Kamailio IP (e.g., `10.5.4.1`).
  - **Auto-detects Transport**: Dynamic detection of the correct UDP transport name (e.g., `0.0.0.0-udp`), preventing mismatch errors.
- **Automated Injection**:
  - Creates a temporary PJSIP Trunk & Endpoint in the FreePBX container.
  - **Smart Inbound Routing**:
    - Adds Proxy IP to `identify` list for authenticated routing.
    - Injects **Dialplan Fallbacks** (`[ext-did-custom]`) to catch "Anonymous" calls if authentication fails.
- **Safety**: All temporary configurations are automatically removed (cleaned up) after the test completes.

## Project Structure

- `agents/`: logic modules (Registration, DNS, Inbound/Outbound calls, Analysis).
- `core/`: Low-level SIP transport and message parsing.
- `utils/`: Logging helpers.
- `docs/agents/`: Detailed architecture documentation (local only).

## License

Distributed under the MIT License. See `LICENSE` for more information.
