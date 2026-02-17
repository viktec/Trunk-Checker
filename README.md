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

## Usage Scenarios

### 1. Direct SIP Testing (Local / Node Direct)
**Goal:** Verify registration and calls by connecting **directly** to the Provider's SIP Server (bypassing local proxies).

- **Where to run**: Local machine, or on the Node/Server itself.
- **Steps**:
  1.  Clone the repository:
      ```bash
      git clone https://github.com/viktec/Trunk-Checker.git
      cd Trunk-Checker
      ```
  2.  Run the script:
      ```bash
      python main.py
      ```
  3.  Select **Option 1: Direct SIP Test**.
  4.  Enter credentials. The tool acts as a standalone SIP Endpoint.

### 2. NethVoice/Kamailio Proxy Testing (Module Integration)
**Goal:** Verify if the NethVoice Proxy (Kamailio) correctly handles the Trunk traffic (Registration/Inbound/Outbound).

- **Where to run**: Inside the NethVoice container/module (e.g., `nethvoice1`).
- **Steps**:
  1.  Access the node via SSH.
  2.  Enter the NethVoice module environment:
      ```bash
      runagent -m nethvoice1  # Replace with actual module name (e.g. nethvoice14, nethvoice1)
      ```
  3.  Clone or access the repository inside the module.
  4.  Run the script:
      ```bash
      python main.py
      ```
  5.  Select **Option 2: NethVoice Proxy Test**.
  6.  Follow the prompts. The script will automatically:
      - Inject config into Asterisk.
      - Register via the internal Proxy (10.5.x.x).
      - Test Inbound/Outbound routing via the Proxy.

### Test Execution Lifecycle
Once running (in either mode), the tool performs the following checks:

1.  **DNS Analysis**: Checks NAPTR and SRV records to determine correct transport (UDP/TCP/TLS) and target IP.
2.  **Registration**: Attempts SIP REGISTER using Digest Authentication.
3.  **Inbound Call Test** (Optional): Listens for an incoming call to verify route headers and codecs negotiation.
4.  **Outbound Call Test** (Optional): Initiates a call to a destination to verify authorization and early media.
5.  **Final Report**: Generates a detailed checklist covering:
    - RFC Compliance (Standard headers)
    - Feature Support (PRACK, Session Timers, 100rel)
    - Security (SRTP, Identity Headers)
    - Codecs Negotiation (G711, G729, Opus, etc.)

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
